/*
 * Copyright (C) 2022 TON Labs. All Rights Reserved.
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

use std::{convert::TryInto, sync::{Arc, Mutex}};

use ed25519::signature::Signature;
use ed25519_dalek::{PublicKey, Verifier};

use ton_types::{
    Result, SliceData, HashmapE, Cell, HashmapType, ExceptionCode,
    serialize_tree_of_cells, deserialize_tree_of_cells
};
use ton_vm::{
    executor::{CommittedState, BehaviorModifiers, Engine, EngineTraceInfo, gas::gas_state::Gas},
    SmartContractInfo, stack::{StackItem, integer::IntegerData},
};
use wasmer::{
    imports, Store, Module, Instance, Value, WasmPtr,
    Function, wasmparser::Operator, CompilerConfig, EngineBuilder, Imports, FunctionEnvMut, FunctionEnv, FunctionType, Type, Memory
};
use wasmer_compiler_singlepass::Singlepass;
use wasmer_middlewares::{
    Metering, metering::{get_remaining_points, set_remaining_points, MeteringPoints},
};

use crate::{VM, TransactionStack};

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
        }
    }
    fn read_bool(&mut self) -> Result<bool> {
        self.read_u8().and_then(|v| Ok(v != 0))
    }
    fn read_u8(&mut self) -> Result<u8> {
        let bytes = &self.bytes[self.pos..self.pos + 1];
        let byte = u8::from_be_bytes(bytes.try_into()?);
        self.pos += 1;
        Ok(byte)
    }
    fn read_u32(&mut self) -> Result<u32> {
        let bytes = &self.bytes[self.pos..self.pos + 4];
        let v = u32::from_be_bytes(bytes.try_into()?);
        self.pos += 4;
        Ok(v)
    }
    fn read_cell(&mut self) -> Result<Cell> {
        let mut cur = std::io::Cursor::new(&self.bytes[self.pos..]);
        let v = deserialize_tree_of_cells(&mut cur)?;
        self.pos += cur.position() as usize;
        Ok(v)
    }
}

struct WasmEnv {
    memory: Option<Memory>,
    accepted: Arc<Mutex<bool>>,
}

impl WasmEnv {
    pub fn memory(&self) -> &Memory {
        self.memory.as_ref().unwrap()
    }
}

pub struct WasmVM {
    is_ext_msg: bool,
    gas: Gas,
    output: CommittedState,
    exit_code: i32,

    store: Store,
    module: Module,
    input: Vec<u8>,
}

impl WasmVM {
    pub fn new(
        code: SliceData,
        data: Cell,
        sci: Option<SmartContractInfo>,
        stack: TransactionStack,
        gas: Option<Gas>,
    ) -> Result<Self> {
        let is_ext_msg = match &stack {
            TransactionStack::Ordinary(stack) => stack.is_ext_msg,
            _ => false,
        };

        let bytecode = Self::make_bytecode(code)?;
        let input = Self::make_input(data, sci.unwrap_or_default(), stack)?;
        log::debug!(target: "executor", "wasm bytecode {}, input {}", bytecode.len(), input.len());

        let cost_function = |_: &Operator| -> u64 { 1 };
        let metering = Arc::new(Metering::new(0, cost_function));
        let mut compiler_config = Singlepass::default();
        compiler_config.push_middleware(metering);

        let store = Store::new(EngineBuilder::new(compiler_config));
        let module = Module::from_binary(&store, &bytecode)?;

        Ok(Self {
            is_ext_msg,
            gas: gas.unwrap_or(Gas::empty()),
            output: CommittedState::new_empty(),
            exit_code: 0,
            store,
            module,
            input,
        })
    }
    fn make_bytecode(code: SliceData) -> Result<Vec<u8>> {
        let dict_cell = code.reference(0)?;
        let dict = HashmapE::with_hashmap(16, Some(dict_cell));
        let mut bytecode = vec!();
        for kv in dict.into_iter() {
            let (_, v) = kv?;
            bytecode.append(&mut v.get_bytestring(0));
        }
        Ok(bytecode)
    }
    fn serialize_hashmap(h: &HashmapE) -> Result<Vec<u8>> {
        let mut bytes = vec!();
        let bits = h.bit_len() as u32;
        bytes.append(&mut Vec::from(bits.to_be_bytes()));
        if let Some(cell) = h.data() {
            bytes.push(0x01);
            bytes.append(&mut Self::serialize_cell(cell)?);
        } else {
            bytes.push(0x00);
        }
        Ok(bytes)
    }
    fn serialize_cell(c: &Cell) -> Result<Vec<u8>> {
        let mut b = vec!();
        serialize_tree_of_cells(&c, &mut b)?;
        Ok(b)
    }
    fn serialize_lazy_cell(c: &Cell) -> Result<Vec<u8>> {
        let mut bytes = Self::serialize_cell(c)?;
        let mut b = vec!();
        b.append(&mut Vec::from((bytes.len() as u32).to_be_bytes()));
        b.append(&mut bytes);
        Ok(b)
    }
    fn serialize_slice(s: &SliceData) -> Result<Vec<u8>> {
        let mut bytes = vec!();
        let data_start = s.pos() as u16;
        let data_end = s.remaining_bits() as u16 + data_start;
        let refs_start = s.get_references().start as u8;
        let refs_end = s.get_references().end as u8;
        bytes.append(&mut Vec::from(data_start.to_be_bytes()));
        bytes.append(&mut Vec::from(data_end.to_be_bytes()));
        bytes.push(refs_start);
        bytes.push(refs_end);
        bytes.append(&mut Self::serialize_cell(s.cell())?);
        Ok(bytes)
    }
    fn serialize_rand_seed(rand_seed: &IntegerData) -> Result<Vec<u8>> {
        Ok(rand_seed.take_value_of(|v| {
            let (_sign, mut biguint) = v.to_bytes_be();
            // TODO check sign is Plus
            let mut bytes = vec!(0x00; 32 - biguint.len());
            bytes.append(&mut biguint);
            Some(bytes)
        })?)
    }
    fn make_input(data: Cell, sci: SmartContractInfo, stack: TransactionStack) -> Result<Vec<u8>> {
        let mut res = vec!();
        { // storage
            let mut bytes = vec!();
            serialize_tree_of_cells(&data, &mut bytes).unwrap();
            res.append(&mut bytes);
        }
        { // params
            let mut bytes = vec!();
            bytes.append(&mut Vec::from(sci.actions.to_be_bytes()));
            bytes.append(&mut Vec::from(sci.msgs_sent.to_be_bytes()));
            bytes.append(&mut Vec::from(sci.unix_time.to_be_bytes()));
            bytes.append(&mut Vec::from(sci.block_lt.to_be_bytes()));
            bytes.append(&mut Vec::from(sci.trans_lt.to_be_bytes()));
            bytes.append(&mut Vec::from(sci.seq_no.to_be_bytes()));
            let mut rand_seed = Self::serialize_rand_seed(&sci.rand_seed)?;
            bytes.append(&mut rand_seed);
            bytes.append(&mut Vec::from(sci.balance.grams.as_u128().to_be_bytes()));
            let balance_other = HashmapE::with_hashmap(32, sci.balance.other.root().cloned());
            bytes.append(&mut Self::serialize_hashmap(&balance_other)?);
            bytes.append(&mut Vec::from(sci.balance_remaining_grams.to_be_bytes()));
            bytes.append(&mut Self::serialize_hashmap(&sci.balance_remaining_other)?);
            bytes.append(&mut Self::serialize_slice(&sci.myself)?);
            bytes.append(&mut Self::serialize_lazy_cell(sci.config_params.as_ref().unwrap_or(&Cell::default()))?);
            bytes.append(&mut Self::serialize_lazy_cell(&sci.mycode)?);
            bytes.append(&mut sci.init_code_hash.as_array().to_vec());
            bytes.append(&mut Vec::from(sci.storage_fee_collected.to_be_bytes()));
            bytes.append(&mut Vec::from(sci.capabilities.to_be_bytes()));
            res.append(&mut bytes);
        }
        { // txn
            let mut bytes = vec!();
            match &stack {
                TransactionStack::Ordinary(t) => {
                    bytes.push(0x01);
                    bytes.append(&mut Vec::from(t.acc_balance.to_be_bytes()));
                    bytes.append(&mut Vec::from(t.msg_balance.to_be_bytes()));
                    bytes.append(&mut Self::serialize_lazy_cell(&t.in_msg_cell)?);
                    bytes.append(&mut Self::serialize_slice(&t.in_msg_body)?);
                    bytes.push(if t.is_ext_msg { 0x01 } else { 0x00 });
                }
                TransactionStack::TickTock(t) => {
                    bytes.push(0x00);
                    bytes.append(&mut Vec::from(t.acc_balance.to_be_bytes()));
                    bytes.append(&mut t.account_id.as_array().to_vec());
                    bytes.push(if t.is_tock { 0x01 } else { 0x00 });
                }
                TransactionStack::Uninit => {
                    unreachable!()
                }
            }
            res.append(&mut bytes);
        }
        Ok(res)
    }
    fn make_imports(&mut self, function_env: &FunctionEnv<WasmEnv>) -> Imports {
        let accept = Function::new_typed_with_env(&mut self.store, &function_env, |env: FunctionEnvMut<WasmEnv>| {
            *env.data().accepted.lock().unwrap() = true;
        });
        let print_signature = FunctionType::new(vec![Type::I32], vec![]);
        let print = Function::new(&mut self.store, &print_signature, |args| {
            println!("PRINT {:08x}", args[0].unwrap_i32());
            Ok(vec!())
        });
        let print3_signature = FunctionType::new(vec![Type::I32, Type::I32, Type::I32], vec![]);
        let print3 = Function::new(&mut self.store, &print3_signature, |args| {
            let is_alloc = args[0].unwrap_i32();
            let ptr = args[1].unwrap_i32();
            let size = args[2].unwrap_i32();
            println!("{} {:08x} {}", if is_alloc == 1 { "ALLOC" } else { "DEALL" }, ptr, size);
            Ok(vec!())
        });
        let chksignu = Function::new_typed_with_env(&mut self.store, &function_env,
            |env: FunctionEnvMut<WasmEnv>, h: u32, s: u32, k: u32| {
                let memory = env.data().memory();
                let view = memory.view(&env);
                
                let mut hash = vec!(0; 32);
                if view.read(h as u64, &mut hash).is_err() {
                    return 2; // TODO name constants
                }
                let mut signature = vec!(0; 64);
                if view.read(s as u64, &mut signature).is_err() {
                    return 3;
                }
                let mut pubkey = vec!(0; 32);
                if view.read(k as u64, &mut pubkey).is_err() {
                    return 4;
                }

                if let Ok(signature) = Signature::from_bytes(&signature) {
                    if let Ok(pubkey) = PublicKey::from_bytes(&pubkey) {
                        if pubkey.verify(&hash, &signature).is_ok() {
                            return 0;
                        }
                    }
                }
                return 1;
            }
        );
        imports! {
            "env" => {
                "accept" => accept,
                "print" => print,
                "print3" => print3,
                "chksignu" => chksignu,
            }
        }
    }
    fn read_output(&mut self, memory: &Memory, output_ptr: Value) -> Result<()> {
        let view = memory.view(&self.store);

        let out_ptr = output_ptr.unwrap_i32() as u32;
        let new_data_ptr = WasmPtr::<u32>::new(out_ptr).deref(&view).read().unwrap();
        let new_data_size = WasmPtr::<u32>::new(out_ptr + 4).deref(&view).read().unwrap();

        let mut output = vec!(0x00; new_data_size as usize);
        view.read(new_data_ptr as u64, &mut output)?;

        let mut c = Cursor::new(&output);
        self.exit_code = c.read_u32()? as i32;
        let is_committed = c.read_bool()?;
        let storage = c.read_cell()?;
        let actions = c.read_cell()?;
        if !is_committed {
            self.output = CommittedState::new_empty();
        } else {
            self.output = CommittedState::with_params(
                StackItem::Cell(storage),
                StackItem::Cell(actions),
            );
        }
        Ok(())
    }
}

const GAS_FACTOR: u64 = 666;
const GAS_FOR_ALLOC: u64 = 10000;

impl VM for WasmVM {
    fn modify_behavior(&mut self, _modifiers: BehaviorModifiers) {
    }
    fn set_trace_callback(&mut self, _callback: Box<dyn Fn(&Engine, &EngineTraceInfo) + Send + Sync + 'static>) {
    }
    fn execute(&mut self) -> Result<i32> {
        let function_env = FunctionEnv::new(
            &mut self.store,
            WasmEnv {
                memory: None,
                accepted: Arc::new(Mutex::new(false)),
            }
        );
        let import_object = self.make_imports(&function_env);
        let instance = Instance::new(&mut self.store, &self.module, &import_object)?;

        // alloc(size: i32) -> *mut u8
        let alloc = instance.exports.get_function("alloc")?;
        // entry(output_ptr: *mut u8, input_ptr: *const u8, input_size: i32)
        let entry = instance.exports.get_function("entry")?;
        // Entire guest memory
        let memory = instance.exports.get_memory("memory")?;
        function_env.as_mut(&mut self.store).memory = Some(memory.clone());

        // Allocate guest memory for input data
        set_remaining_points(&mut self.store, &instance, GAS_FOR_ALLOC);
        let input_size = Value::I32(self.input.len() as i32);
        // TODO get rid of [0]
        let input_ptr = alloc.call(&mut self.store, &[input_size.clone()])?.to_vec()[0].clone();
        // Write input data starting from the offset given by the input ptr
        let view = memory.view(&mut self.store);
        let offset = input_ptr.i32().unwrap() as u64;
        view.write(offset, &self.input)?;
        // Allocate a structure of two 4-bytes fields:
        //  - output data ptr
        //  - output data size
        set_remaining_points(&mut self.store, &instance, GAS_FOR_ALLOC);
        let output_ptr = alloc.call(&mut self.store, &[Value::I32(8)])?.to_vec()[0].clone();

        // Compute initial gas offering
        let remaining_gas = self.gas.get_gas_limit() + self.gas.get_gas_credit();
        let initial_limit = remaining_gas as u64 * GAS_FACTOR;
        log::debug!(target: "executor", "metering limit {}", initial_limit);
        set_remaining_points(&mut self.store, &instance, initial_limit);

        // Execute contract's entry function for the first time
        let res = entry.call(&mut self.store, &[output_ptr.clone(), input_ptr.clone(), input_size.clone()]);
        match get_remaining_points(&mut self.store, &instance) {
            MeteringPoints::Remaining(rem) => {
                log::debug!(target: "executor", "points remaining {}", rem);
                if self.is_ext_msg {
                    // Execution completed "for free" using credit gas only
                    self.gas.new_gas_limit(i64::MAX);
                } else {
                    // otherwise, account for used gas
                    self.gas.use_gas(((initial_limit - rem) / GAS_FACTOR) as i64);
                }
            }
            MeteringPoints::Exhausted => {
                let accepted = *function_env.as_ref(&mut self.store).accepted.lock().unwrap();
                if self.is_ext_msg && accepted {
                    // Let transaction executor know there was an accept
                    self.gas.new_gas_limit(i64::MAX);

                    // Set secondary gas offering after accept
                    let secondary_limit = self.gas.get_gas_remaining() as u64 * GAS_FACTOR;
                    log::debug!(target: "executor", "secondary metering limit {}", secondary_limit);
                    set_remaining_points(&mut self.store, &instance, secondary_limit);

                    // Execute contract's entry point for the second time
                    let res2 = entry.call(&mut self.store, &[output_ptr.clone(), input_ptr, input_size]);
                    match get_remaining_points(&mut self.store, &instance) {
                        MeteringPoints::Remaining(rem) => {
                            log::debug!(target: "executor", "points remaining {}", rem);
                            self.gas.use_gas(((secondary_limit - rem) / GAS_FACTOR) as i64);
                        }
                        MeteringPoints::Exhausted => {
                            return Result::Err(ExceptionCode::OutOfGas.into())
                        }
                    }
                    if let Err(e) = res2 {
                        log::debug!(target: "executor", "{}", e);
                        return Result::Err(ExceptionCode::FatalError.into())
                    }
                } else {
                    return Result::Err(ExceptionCode::OutOfGas.into())
                }
            }
        }
        if let Err(e) = res {
            log::debug!(target: "executor", "{}", e);
            return Result::Err(ExceptionCode::FatalError.into())
        }

        self.read_output(memory, output_ptr)?;
        log::debug!(target: "executor", "wasm exit code: {}", self.exit_code);

        Ok(self.exit_code)
    }
    fn steps(&self) -> u32 {
        100000
    }
    fn get_committed_state(&self) -> &CommittedState {
        &self.output
    }
    fn get_gas(&self) -> &Gas {
        &self.gas
    }
}
