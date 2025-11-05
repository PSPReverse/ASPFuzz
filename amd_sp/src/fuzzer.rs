//! A fuzzer using qemu in systemmode for binary-only coverage of kernels
//!
use core::{ptr::addr_of_mut, time::Duration};
use std::process;

use crate::setup::{parse_args, setup_directory_structure};
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{ClientDescription, EventConfig, Launcher},
    executors::ExitKind,
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    current_nanos,
    ownedref::OwnedMutSlice,
    prelude::Cores,
    rands::{RomuDuoJrRand, StdRand},
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Prepend},
};
use libafl_qemu::{
    executor::QemuExecutor,
    modules::{
        edges::StdEdgeCoverageModuleBuilder,
        utils::filters::{HasAddressFilter, StdAddressFilter},
        DrCovModule,
    },
    Emulator, QemuExitError, QemuExitReason, QemuParams, QemuShutdownCause, Regs,
};

use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use libasp::{
    config::{
        access_observer::{AccessObserverFeedback, AccessObserverObserver},
        get_run_conf,
    },
    read_mailbox_value, CustomMetadataFeedback, ExceptionFeedback, MiscMetadata, RegisterMetadata,
};
use rangemap::RangeMap;

pub type MyState =
    StdState<CachedOnDiskCorpus<BytesInput>, BytesInput, RomuDuoJrRand, OnDiskCorpus<BytesInput>>;

pub fn fuzz() -> Result<(), Error> {
    //env_logger::init();



    fn init_logger() {
        use env_logger::{Builder, Env};
        use std::io::Write;


        let env = Env::default();

        Builder::from_env(env)
            .format(|buf, record| {
                // We are reusing `anstyle` but there are `anstyle-*` crates to adapt it to your
                // preferred styling crate.
                let warn_style = buf.default_level_style(log::Level::Warn);
                let timestamp = buf.timestamp();
                let threadid =
                    process::id();

                writeln!(
                    buf,
                    "thid({threadid:?}) ({timestamp}): {warn_style}{}{warn_style:#}",
                    record.args()
                )
            })
            .init();
    }

    init_logger();

    let args = Box::new(parse_args());
    let conf = get_run_conf().ok_or(Error::empty_optional("No run configuration found"))?;

    let (input_dir, log_dir, solutions_dir) =
        setup_directory_structure(&conf.run_dir, &conf.config_path)?;
    // Generate initial inputs
    conf.yaml_config
        .input
        .create_initial_inputs(conf.yaml_config.flash.size, &input_dir);
    let input_dir = Box::new(input_dir);
    let mut run_client = move |state: Option<MyState>,
                               mut mgr,
                               client_description: ClientDescription| {
        log::error!("Starting client");
        let conf = get_run_conf().unwrap();
        // Configure DrCov helper
        let mut log_drcov_path = log_dir.clone();
        log_drcov_path.push("drcov.log");
        let mut rangemap = RangeMap::<u64, (u16, String)>::new();

        // TODO: Should this be dynamic?
        rangemap.insert(
            0x0_u64..0xffff_9000_u64,
            (0, "on-chip-ryzen-zen.bl".to_string()),
        );
        #[allow(clippy::single_range_in_vec_init)]
        let filter = StdAddressFilter::deny_list(vec![0x0_u32..0xffff_ffff_u32]);
        // Configure QEMU hook helper
        let dr_cov_module = DrCovModule::builder()
            .module_mapping(rangemap)
            .filename(log_drcov_path)
            .filter(filter)
            .full_trace(false)
            .build();
        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                addr_of_mut!(MAX_EDGES_FOUND),
            ))
            .track_indices()
        };
        let emulator_modules = conf
            .yaml_config
            .get_emulator_modules::<MyState>()
            .prepend(
                StdEdgeCoverageModuleBuilder::default()
                    .map_observer(edges_observer.as_mut())
                    .build()?,
            )
            .prepend(dr_cov_module);
        let args = args.as_ref();
        let emulator = Emulator::empty()
            .qemu_parameters(QemuParams::Cli(args.clone()))
            .modules(emulator_modules)
            .build()?;
        let qemu = emulator.qemu();
        let start_addr = conf.yaml_config.harness.start;
        qemu.set_breakpoint(start_addr);

        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(guest_addr)) => {
                    assert_eq!(
                        guest_addr, start_addr,
                        "Guest addr: {guest_addr:#x}, Conf harness: {start_addr:#x}"
                    );
                }
                _ => panic!("Unexpected QEMU exit."),
            }
        }
        qemu.remove_breakpoint(start_addr);
        for &s in &conf.yaml_config.harness.sinks {
            qemu.set_breakpoint(s); // BREAKPOINT
        }

        // let saved_cpu_states: Vec<_> = (0..emu.num_cpus())
        //     .map(|i| emu.cpu_from_index(i).save_state())
        //     .collect();

        // emu.save_snapshot("start", true);

        let snap = emulator.create_fast_snapshot(true);
        log::error!("Snapshot created");
        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, MyState, _>,
                           state: &mut MyState,
                           input: &BytesInput| {
            log::error!("Starting harness");
            let dr_cov_module = emulator
                .modules_mut()
                .get_mut::<DrCovModule<StdAddressFilter>>()
                .unwrap();
            dr_cov_module.update_address_filter(
                qemu,
                // Empty allow list allows everything
                StdAddressFilter::allow_list(vec![]),
            );
            conf.yaml_config.input.apply_input(input);
            log::error!("Starting QEMU");
            unsafe {
                let res = emulator.qemu().run();
                // TODO: Figure out how do do this in an observer
                // Doing this in an EmulatorModule results in a read after the snapshot has been restored
                state.metadata_map_mut().insert(RegisterMetadata::new(qemu));
                state.add_metadata(MiscMetadata {
                    mailbox_values: read_mailbox_value(&qemu.cpu_from_index(0).unwrap())
                        .expect("Failed to read mailbox"),
                });

                match res {
                    Ok(QemuExitReason::Breakpoint(_)) => {} // continue execution, nothing to do there.
                    Ok(QemuExitReason::Timeout) => {
                        let pc: u32 = qemu.cpu_from_index(0).unwrap().read_reg(Regs::Pc).unwrap();
                        log::error!("Timeout at {:#x}", pc);
                        return ExitKind::Timeout;
                    } // timeout, propagate
                    Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                        log::error!("HostSignal");
                        // will take care of cleanly stopping the fuzzer.
                        signal.handle();
                    }

                    Err(QemuExitError::UnexpectedExit) => {
                        log::error!("Crash");
                        return ExitKind::Crash;
                    }
                    e => panic!("Unexpected QEMU exit: {e:?}."),
                }

                // If the execution stops at any point other than the designated breakpoint (e.g. a breakpoint on a panic method) we consider it a crash
                let pc: u32 = qemu.cpu_from_index(0).unwrap().read_reg(Regs::Pc).unwrap();
                let ret = if conf.yaml_config.harness.sinks.contains(&pc) {
                    ExitKind::Ok
                } else {
                    log::error!("Unexpected exit at PC: {pc:#x}");
                    ExitKind::Crash
                };
                log::error!("Harness done with exit code {ret:?}");
                // OPTION 1: restore only the CPU state (registers et. al)
                // for (i, s) in saved_cpu_states.iter().enumerate() {
                //     emu.cpu_from_index(i).restore_state(s);
                // }

                // OPTION 2: restore a slow vanilla QEMU snapshot
                // emu.load_snapshot("start", true);

                // OPTION 3: restore a fast devices+mem snapshot
                emulator.restore_fast_snapshot(snap);
                ret
            }
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");
        let time_feedback = TimeFeedback::new(&time_observer);
        let access_observer = AccessObserverObserver::new(conf.yaml_config.crashes.x86.clone());

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            time_feedback.clone()
        );
        let objective_map_feedback =
            MaxMapFeedback::with_name("objective_map_feedback", &edges_observer);

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(
            feedback_or!(
                AccessObserverFeedback::new(&access_observer),
                feedback_and_fast!(
                    feedback_or_fast!(CrashFeedback::new(), ExceptionFeedback::default()),
                    // Only report those crashes that resulted in new coverage
                    objective_map_feedback,
                ),
            ),
            // Always false but adds metadata to the output
            feedback_or!(CustomMetadataFeedback::default(), time_feedback)
        );

        // If not restarting, create a State from scratch
        let mut state: MyState = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos() + client_description.id() as u64),
                // Corpus that will be evolved, we keep it in memory for performance
                CachedOnDiskCorpus::new(&*input_dir, 1000).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(solutions_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let timeout = Duration::from_secs(10);

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer, time_observer, access_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(
                    &mut fuzzer,
                    &mut executor,
                    &mut mgr,
                    &[input_dir.as_ref().clone()],
                )
                .unwrap_or_else(|_| {
                    log::error!("Failed to load initial corpus at {:?}", &input_dir);
                    process::exit(0);
                });
            log::info!("We imported {} inputs from disk.", state.corpus().count());
        }

        // Setup an havoc mutator with a mutational stage
        let mutator = HavocScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| log::info!(target: "aspfuzz_updates","{s}"));
    // let monitor = SimpleMonitor::new(|s| log::info!("{s}"));
    // let mgr = SimpleEventManager::new(monitor);
    // run_client(None, mgr, 0)

    //Build and run a Launcher
    let num_cores = get_run_conf().unwrap().num_cores;
    let cores = Cores::from_cmdline(&format!("0-{num_cores}")).unwrap();
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        // .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => Ok(()),
        Err(Error::ShuttingDown) => {
            log::error!("Fuzzing stopped by user. Good bye.");
            Ok(())
        }
        Err(err) => Err(err),
    }
}
