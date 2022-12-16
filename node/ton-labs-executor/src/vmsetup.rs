/*
* Copyright (C) 2019-2022 TON Labs. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

use ton_types::{Cell, HashmapE, SliceData, Result};
use ton_vm::{
    executor::{Engine, gas::gas_state::Gas, BehaviorModifiers, EngineTraceInfo}, smart_contract_info::SmartContractInfo,
    stack::{StackItem, savelist::SaveList}
};
use crate::{wasm::WasmVM, TransactionStack};

use ton_vm::executor::CommittedState;

pub trait VM {
    fn modify_behavior(&mut self, modifiers: BehaviorModifiers);
    fn set_trace_callback(&mut self, callback: Box<dyn Fn(&Engine, &EngineTraceInfo) + Send + Sync + 'static>);
    fn execute(&mut self) -> Result<i32>;
    fn steps(&self) -> u32;
    fn get_committed_state(&self) -> &CommittedState;
    fn get_gas(&self) -> &Gas;
}

#[derive(PartialEq)]
pub enum VMKind {
    TVM,
    WasmVM
}

/// Builder for virtual machine engine. Initialises registers,
/// stack and code of VM engine. Returns initialized instance of TVM.
pub struct VMSetup {
    kind: VMKind,
    capabilities: u64,
    code: SliceData,
    sci: Option<SmartContractInfo>,
    data: Cell,
    stack: TransactionStack,
    gas: Option<Gas>,
    libraries: Vec<HashmapE>,
    debug: bool,
}

struct TVM {
    vm: Engine
}
impl VM for TVM {
    fn modify_behavior(&mut self, modifiers: BehaviorModifiers) {
        self.vm.modify_behavior(modifiers)
    }
    fn set_trace_callback(&mut self, callback: Box<dyn Fn(&Engine, &EngineTraceInfo) + Send + Sync + 'static>) {
        self.vm.set_trace_callback(callback)
    }
    fn execute(&mut self) -> Result<i32> {
        self.vm.execute()
    }
    fn steps(&self) -> u32 {
        self.vm.steps()
    }
    fn get_committed_state(&self) -> &CommittedState {
        self.vm.get_committed_state()
    }
    fn get_gas(&self) -> &Gas {
        self.vm.get_gas()
    }
}

impl VMSetup {

    /// Creates new instance of VMSetup with contract code.
    /// Initializes some registers of TVM with predefined values.
    pub fn with_capabilites(code: SliceData, capabilities: u64) -> Self {
        let bytes = code.get_bytestring(0);
        let kind = if bytes == &[0xff, 0xee] {
            log::debug!(target: "executor", "wasm bytecode detected");
            VMKind::WasmVM
        } else {
            log::debug!(target: "executor", "tvm bytecode detected");
            VMKind::TVM
        };
        VMSetup {
            kind,
            capabilities,
            code,
            data: Cell::default(),
            sci: None,
            stack: TransactionStack::Uninit,
            gas: Some(Gas::empty()),
            libraries: vec![],
            debug: false,
        }
    }

    pub fn set_smart_contract_info(mut self, sci: SmartContractInfo) -> Self {
        debug_assert_ne!(sci.capabilities, 0);
        self.sci = Some(sci);
        self
    }

    /// Sets persistent data for contract in register c4
    pub fn set_data(mut self, data: Cell) -> Self {
        self.data = data;
        self
    }

    /// Sets initial stack for TVM
    pub fn set_stack(mut self, stack: TransactionStack) -> Self {
        self.stack = stack;
        self
    }
    
    /// Sets gas for TVM
    pub fn set_gas(mut self, gas: Gas) -> Self {
        self.gas = Some(gas);
        self
    }

    /// Sets libraries for TVM
    pub fn set_libraries(mut self, libraries: Vec<HashmapE>) -> Self {
        self.libraries = libraries;
        self
    }

    /// Sets trace flag to TVM for printing stack and commands
    pub fn set_debug(mut self, enable: bool) -> Self {
        self.debug = enable;
        self
    }

    /// Creates new instance of TVM with defined stack, registers and code.
    pub fn create(self) -> Result<Box<dyn VM>> {
        if self.kind == VMKind::WasmVM {
            return Ok(Box::new(WasmVM::new(
                self.code,
                self.data,
                self.sci,
                self.stack,
                self.gas,
            )?))
        }
        if cfg!(debug_assertions) {
            // account balance is duplicated in stack and in c7 - so check
            let balance_in_smc = match &self.sci {
                Some(sci) => sci.balance.grams.as_u128(),
                None => 0,
            };
            let balance_in_stack = match &self.stack {
                TransactionStack::Ordinary(s) => s.acc_balance,
                TransactionStack::TickTock(s) => s.acc_balance,
                TransactionStack::Uninit => 0,
            };
            debug_assert_eq!(balance_in_smc, balance_in_stack);
        }
        let mut vm = Engine::with_capabilities(self.capabilities);
        if self.debug {
            vm.set_trace(Engine::TRACE_ALL);
        } else {
            vm.set_trace(0);
        }
        let mut ctrls = SaveList::new();
        ctrls.put(4, &mut StackItem::Cell(self.data))?;
        if let Some(sci) = self.sci {
            let mut sci = sci.into_temp_data_item();
            ctrls.put(7, &mut sci)?;
        }
        Ok(Box::new(TVM { vm: vm.setup_with_libraries(
            self.code,
            Some(ctrls),
            Some(self.stack.build()),
            self.gas,
            self.libraries
        )}))
    }
}
