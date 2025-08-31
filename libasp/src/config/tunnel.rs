use std::cell::Cell;
use libafl_qemu::{EmulatorModules, GuestAddr, GuestReg, Hook, Qemu, Regs};
use log;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
use std::fmt;
use std::rc::Rc;

#[derive(Clone, Deserialize, Debug)]
pub struct TunnelTrigger{
    hits: Cell<u32>,
    delay: u32,
    firing_amount: u32,
}
impl TunnelTrigger {
    pub fn new(delay: u32, firing_amount: u32) -> Self {
        Self {
            hits: Cell::new(0),
            delay,
            firing_amount,
        }
    }
    pub fn increment_hits(&self) {
        self.hits.set(self.hits.get() + 1);
    }
    pub fn should_trigger(&self) -> bool {
        // before delay is up
        if self.hits.get() < self.delay {
            return false;
        }
        // use 0 as infinity
        if self.firing_amount == 0 {
            return true;
        }
        // false again after firing_amount is up
        if self.hits.get() > self.delay + self.firing_amount {
            return false;
        }
        true
    }
}



#[derive(Clone, Deserialize, Debug)]
#[serde(tag = "action")]
pub enum CmpAction {
    CopyRegister {
        #[serde(deserialize_with = "parse_regs")]
        target: Regs,
        #[serde(deserialize_with = "parse_regs")]
        source: Regs,
    },
    SetConstant {
        #[serde(deserialize_with = "parse_regs")]
        target: Regs,
        value: GuestReg,
        delay: Option<u32>,
        exec_amount: Option<u32>,
    },
    Jump {
        source: GuestAddr,
        target: GuestAddr,
        delay: Option<u32>,
        exec_amount: Option<u32>,
    },
    PermaJump {
        source: GuestAddr,
        target: GuestAddr,
    },
    LogRegister {
        #[serde(deserialize_with = "parse_regs")]
        target: Regs,
    },
    WriteMemory {
        target: GuestAddr,
        value: String,
        delay: Option<u32>,
        exec_amount: Option<u32>,
    },
    LogMemory {
        target: GuestAddr,
        size: usize,
    },
}
#[derive(Clone, Deserialize, Debug)]
pub struct TunnelActions {
    addr: GuestAddr,
    #[serde(flatten)]
    value: CmpAction,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(transparent)]
pub struct TunnelConfig {
    actions: Vec<TunnelActions>,
}

impl TunnelConfig {
    pub fn setup<ET, I, S>(&self, emu_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: Unpin,
        S: Unpin,
        I: Unpin,
    {
        for TunnelActions {
            addr,
            value: action,
        } in self.actions.clone()
        {
            match action {
                CmpAction::SetConstant { target, value , delay, exec_amount} => {
                    let trigger_info = Rc::new(TunnelTrigger::new(delay.unwrap_or(0), exec_amount.unwrap_or(0)));
                    emu_modules.instructions(
                    addr,
                    Hook::Closure(Box::new({
                        let trigger_info = Rc::clone(&trigger_info);
                        move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                            trigger_info.increment_hits();
                            if !trigger_info.should_trigger() {
                                log::debug!("Tunnel - Constant [{addr:#x}, {target:?}, {value:#x}] skipping");
                                return;
                            }

                            log::debug!("Tunnel - Constant [{addr:#x}, {target:?}, {value:#x}]");
                            qemu.write_reg(target, value).unwrap();
                        }
                    })),
                    true,
                )},
                CmpAction::CopyRegister { target, source } => emu_modules.instructions(
                    addr,
                    Hook::Closure(Box::new(
                        move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                            log::debug!("Tunnel - Register [{addr:#x}, {target:?}, {source:?}]");

                            let value: u32 = qemu.read_reg(source).unwrap();
                            qemu.write_reg(target, value).unwrap();
                        },
                    )),
                    false,
                ),
                CmpAction::Jump {
                    source,
                    target,
                    delay,
                    exec_amount,
                } => {
                    let trigger_info = Rc::new(TunnelTrigger::new(delay.unwrap_or(0), exec_amount.unwrap_or(0)));
                    emu_modules.instructions(
                        addr,
                        Hook::Closure(Box::new({
                            let trigger_info = Rc::clone(&trigger_info);
                            move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                                trigger_info.increment_hits();
                                if !trigger_info.should_trigger() {
                                    log::debug!("Tunnel - Jump [{addr:#x},{source:#x}, {target:#x}] skipping");
                                    return;
                                }

                                log::debug!("Tunnel - Jump [{addr:#x},{source:#x}, {target:#x}] triggering");
                                let inst: [u8; 2] = generate_branch_call(source, target);
                                // Patch the instruction by overwriting it
                                qemu.write_mem(source, &inst)
                                    .expect("Overwriting instruction failed");
                                qemu.flush_jit();
                            }
                        })),
                        true,
                    )
                }
                CmpAction::PermaJump { source, target } => emu_modules.instructions(
                    addr,
                    Hook::Closure(Box::new(
                        move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                            log::debug!("Tunnel - Jump [{addr:#x},{source:#x}, {target:#x}]");
                            let inst: [u8; 2] = generate_branch_call(source, target);
                            // Patch the instruction by overwriting it
                            qemu.write_mem(source, &inst)
                                .expect("Overwriting instruction failed");

                            qemu.flush_jit();
                        },
                    )),
                    false,
                ),
                CmpAction::LogRegister { target } => emu_modules.instructions(
                    addr,
                    Hook::Closure(Box::new(
                        move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                            let value: u32 = qemu.read_reg(target).unwrap();
                            log::debug!("Tunnel - Log [{addr:#x}, {target:?}, {value:#x}]");
                        },
                    )),
                    false,
                ),
                CmpAction::WriteMemory {
                    target: memory_addr,
                    value,
                    delay,
                    exec_amount,
                } => {
                    let trigger_info = Rc::new(TunnelTrigger::new(delay.unwrap_or(0), exec_amount.unwrap_or(0)));
                    emu_modules.instructions(
                    addr,
                    Hook::Closure(Box::new({
                        let trigger_info = Rc::clone(&trigger_info);
                        move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                            trigger_info.increment_hits();
                            if !trigger_info.should_trigger() {
                                log::debug!("Tunnel - WriteMem [{addr:#x}, {memory_addr:#x}] skipping");
                                return;
                            }

                            let trimmed = value.trim_start_matches("0x");
                            let result = hex::decode(trimmed);
                            match result {
                                Ok(bytes) => {
                                    qemu.write_mem(memory_addr, &*bytes)
                                        .expect("WriteMem failed");
                                    log::debug!(
                                "Tunnel - WriteMem [{addr:#x}, {memory_addr:#x}, {bytes:?}]"
                                );
                                },
                                Err(e) => log::error!("{:?}", e),
                            }
                        }
                    })),
                    true,
                )},
                CmpAction::LogMemory {
                    target: memory_addr,
                    size,
                } => emu_modules.instructions(
                    addr,
                    Hook::Closure(Box::new(
                        move |qemu: Qemu, _hks: &mut EmulatorModules<ET, I, S>, _state, _pc| {
                            let mut buf = vec![0_u8; size];
                            qemu.read_mem(memory_addr, &mut buf)
                                .expect("ReadMem failed");

                            log::debug!(
                                "Tunnel - LogMemory [{addr:#x}, {memory_addr:#x}, {buf:02x?}]"
                            );
                        },
                    )),
                    false,
                ),
            };
        }
    }
}

// TODO handle more encodings this is just the simplest encoding

/// This generates the ARM branch call instruction
fn generate_branch_call(cur_pc: u32, target: u32) -> [u8; 2] {
    let diff = i32::try_from(target).unwrap() - i32::try_from(cur_pc + 4).unwrap();
    let diff = i16::try_from(diff).unwrap();
    assert!((-2048..=2046).contains(&diff));
    assert!(diff % 2 == 0);
    let mask = (1i16 << 11) - 1;
    let inst = (0b11100 << 11) | ((diff / 2) & mask);
    log::info!("Generating jump instruction diff: {diff:#x} inst: {inst:#x}");
    inst.to_le_bytes()
}

fn parse_regs<'de, D>(deserializer: D) -> Result<Regs, D::Error>
where
    D: Deserializer<'de>,
{
    struct RegisterVisitor;
    const VALUES: &[&str] = &["A valid Register name"];
    impl Visitor<'_> for RegisterVisitor {
        type Value = Regs;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("A valid Register name")
        }

        fn visit_str<E>(self, value: &str) -> Result<Regs, E>
        where
            E: de::Error,
        {
            parse_regs2(value).ok_or(de::Error::unknown_field(value, VALUES))
        }
    }
    deserializer.deserialize_str(RegisterVisitor)
}
/// As we do not own the Regs type this is the best we can do
#[must_use]
pub fn parse_regs2(reg: &str) -> Option<Regs> {
    Some(match reg {
        "R0" => Regs::R0,
        "R1" => Regs::R1,
        "R2" => Regs::R2,
        "R3" => Regs::R3,
        "R4" => Regs::R4,
        "R5" => Regs::R5,
        "R6" => Regs::R6,
        "R7" => Regs::R7,
        "R8" => Regs::R8,
        "R9" => Regs::R9,
        "R10" => Regs::R10,
        "R11" => Regs::R11,
        "R12" => Regs::R12,
        "R13" => Regs::R13,
        "R14" => Regs::R14,
        "R15" => Regs::R15,
        "R25" => Regs::R25,
        "Sp" => Regs::Sp,
        "SP" => Regs::Sp,
        "Lr" => Regs::Lr,
        "LR" => Regs::Lr,
        "Pc" => Regs::Pc,
        "PC" => Regs::Pc,
        "Sb" => Regs::Sb,
        "SB" => Regs::Sb,
        "Sl" => Regs::Sl,
        "SL" => Regs::Sl,
        "Fp" => Regs::Fp,
        "FP" => Regs::Fp,
        "Ip" => Regs::Ip,
        "IP" => Regs::Ip,
        "Cpsr" => Regs::Cpsr,
        "CPSR" => Regs::Cpsr,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_register() {
        #[derive(Deserialize, Debug)]

        struct Test {
            #[serde(deserialize_with = "parse_regs")]
            target: Regs,
        }
        let text = "target: R0";
        let t: Test = serde_yaml::from_str(text).unwrap();
        match t.target {
            Regs::R0 => {}
            _ => panic!("Wrong Register"),
        }
    }

    #[test]
    fn generate_good_branch() {
        assert_eq!(generate_branch_call(0x00002a1c, 0x2a22), [0x01, 0xe0]);
        assert_eq!(generate_branch_call(0x00002a1c, 0x2938), [0x8c, 0xe7]);
    }
}
