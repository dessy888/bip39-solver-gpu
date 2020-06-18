use std::fs;
use std::ffi::{CString};
use ocl::{core, flags};
use ocl::prm::{cl_ulong};
use ocl::enums::ArgVal;
use ocl::builders::ContextProperties;
use hex;
use std::str;
use std::collections::HashMap;
use rayon::prelude::*;
use reqwest;
use serde::{Deserialize};
use bitcoin_wallet::mnemonic::Mnemonic;
use bitcoin_wallet::account::{MasterAccount, Unlocker, Account, AccountAddressType};
use bitcoin_wallet::bitcoin::network::constants::Network;
use bitcoin_wallet::bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut, SigHashType, OutPoint};
use bitcoin_wallet::bitcoin::blockdata::script::{Script};
use bitcoin_wallet::bitcoin::blockdata::{script, opcodes};
use bitcoin_wallet::bitcoin::hashes::hex::FromHex;
use bitcoin_wallet::bitcoin::consensus::encode::{serialize, deserialize};

const PASSPHRASE: &str = "";
const WORK_SERVER_URL: &str = "http://localhost:3000";
const WORK_SERVER_SECRET: &str = "secret";
const INPUT_TRANSACTION: &str = "0200000002b927da7d93d6168ada9d471aa4bea50c70323353aae68b39faa08ffc7ae15265010000006a473044022035dc74cb164947397d639ae6e5b148fa2b1f1d6a93239555b4b058425c6328b002206e90486b11da907e35a14b454b17bead964e1507821a99d7fe960d1643d13294012103786af4b32017ec640dba2d2a7e1fd5aa4a231a658e4cbc114d51c031576e19bcffffffff665a5990fd90f1e6457a0704da5a067a6caca6dd91e3e921869ce884bb4af8a6020000006a473044022022dfe92099a3f896ff84fdab6bd1d99c2c8a17d9ecaedd26f093cf444382e7220220118f77d80a36525c1d95f0bd990baa7ffbcf499ccf4f8289b39c2d4ee77e1068012103786af4b32017ec640dba2d2a7e1fd5aa4a231a658e4cbc114d51c031576e19bcffffffff0300e1f5050000000017a914ada12b113d9b19614757d19fc08ddd534bf0227687ea4b04000000000017a9140997ff827d755a356d7ddb83a789b5954611c9c78758f8f698080000001976a914cebb2851a9c7cfe2582c12ecaf7f3ff4383d1dc088ac00000000";

#[derive(Deserialize, Debug)]
struct WorkResponse {
  indices: Vec<u128>,
  offset: u128,
  batch_size: u64
}

struct Work {
  start_hi: u64,
  start_lo: u64,
  batch_size: u64,
  offset: u128
}

fn sweep_btc(mnemonic: String){
  let tx_bytes: Vec<u8> = Vec::from_hex(INPUT_TRANSACTION).unwrap();
  let input_transaction: Transaction = deserialize(&tx_bytes).unwrap();
  
  let mnemonic = Mnemonic::from_str(&mnemonic).unwrap();
  let mut master = MasterAccount::from_mnemonic(&mnemonic, 0, Network::Bitcoin, PASSPHRASE, None).unwrap();
  let mut unlocker = Unlocker::new_for_master(&master, PASSPHRASE).unwrap();
  let account = Account::new(&mut unlocker, AccountAddressType::P2SHWPKH, 0, 0, 10).unwrap();
  master.add_account(account);
  
  // this is the raw address of where to send the coins
  let target_address_bytes = [];
  let amount_to_spend = 99000000;

  let script_pubkey = script::Builder::new()
              .push_opcode(opcodes::all::OP_HASH160)
              .push_slice(&target_address_bytes)
              .push_opcode(opcodes::all::OP_EQUAL).into_script();

  let txid = input_transaction.txid();
  const RBF: u32 = 0xffffffff - 2;

  let mut spending_transaction = Transaction {
      input: vec![
          TxIn {
              previous_output: OutPoint { txid, vout: 0 },
              sequence: RBF,
              witness: Vec::new(),
              script_sig: Script::new(),
          }
      ],
      output: vec![
          TxOut {
              script_pubkey: script_pubkey,
              value: amount_to_spend,
          },
      ],
      lock_time: 0,
      version: 2,
  };

  master.sign(&mut spending_transaction, SigHashType::All, &(|_| Some(input_transaction.output[0].clone())),&mut unlocker).expect("can not sign");
  let rawtx = hex::encode(serialize(&spending_transaction));
  broadcast_tx(rawtx);
}

fn broadcast_tx(rawtx: String) {
  let mut json_body = HashMap::new();
  json_body.insert("tx", rawtx);
  let client = reqwest::blocking::Client::new();
  let _res = client.post("https://api.blockcypher.com/v1/btc/main/txs/push").json(&json_body).send();
}

fn log_solution(offset: u128, mnemonic: String) {
  let mut json_body = HashMap::new();
  json_body.insert("mnemonic", mnemonic);
  json_body.insert("offset", offset.to_string());
  json_body.insert("secret", WORK_SERVER_SECRET.to_string());
  let client = reqwest::blocking::Client::new();
  let _res = client.post(&format!("{}/mnemonic", WORK_SERVER_URL.to_string()).to_string()).json(&json_body).send();
}

fn log_work(offset: u128) {
  let mut json_body = HashMap::new();
  json_body.insert("offset", offset.to_string());
  json_body.insert("secret", WORK_SERVER_SECRET.to_string());
  let client = reqwest::blocking::Client::new();
  let _res = client.post(&format!("{}/work", WORK_SERVER_URL.to_string()).to_string()).json(&json_body).send();
}

fn get_work() -> Work {
  let response = reqwest::blocking::get(&format!("{}/work?secret={}", WORK_SERVER_URL.to_string(), WORK_SERVER_SECRET.to_string()).to_string()).unwrap();
  let work_response: WorkResponse = response.json().unwrap();

  let mut start: u128 = 0;
  let mut start_shift = 128;

  for idx in &work_response.indices {
    start_shift -= 11;
    start = start | (idx << start_shift);
  }

  start += work_response.offset;
  let start_lo: u64 = ((start << 64) >> 64) as u64;
  let start_hi: u64 = (start >> 64) as u64;

  return Work {
    start_lo: start_lo,
    start_hi: start_hi,
    batch_size: work_response.batch_size,
    offset: work_response.offset
  }
}

fn mnemonic_gpu(platform_id: core::types::abs::PlatformId, device_id: core::types::abs::DeviceId, src: std::ffi::CString, kernel_name: &String) -> ocl::core::Result<()> {
  let context_properties = ContextProperties::new().platform(platform_id);
  let context = core::create_context(Some(&context_properties), &[device_id], None, None).unwrap();
  let program = core::create_program_with_source(&context, &[src]).unwrap();
  core::build_program(&program, Some(&[device_id]), &CString::new("").unwrap(), None, None).unwrap();
  let queue = core::create_command_queue(&context, &device_id, None).unwrap();

  loop {
    let work: Work = get_work();
    let items: u64 = work.batch_size;

    let mnemonic_hi: cl_ulong = work.start_hi;
    let mnemonic_lo: cl_ulong = work.start_lo;
    
    let mut target_mnemonic = vec![0u8; 120];
    let mut mnemonic_found = vec![0u8; 1];
    
    let target_mnemonic_buf = unsafe { core::create_buffer(&context, flags::MEM_WRITE_ONLY |
      flags::MEM_COPY_HOST_PTR, 120, Some(&target_mnemonic))? };
    
    let mnemonic_found_buf = unsafe { core::create_buffer(&context, flags::MEM_WRITE_ONLY |
        flags::MEM_COPY_HOST_PTR, 1, Some(&mnemonic_found))? };
  
    let kernel = core::create_kernel(&program, kernel_name)?;

    core::set_kernel_arg(&kernel, 0, ArgVal::scalar(&mnemonic_hi))?;
    core::set_kernel_arg(&kernel, 1, ArgVal::scalar(&mnemonic_lo))?;
    core::set_kernel_arg(&kernel, 2, ArgVal::mem(&target_mnemonic_buf))?;
    core::set_kernel_arg(&kernel, 3, ArgVal::mem(&mnemonic_found_buf))?;

    unsafe { core::enqueue_kernel(&queue, &kernel, 1, None, &[items as usize,1,1],
        None, None::<core::Event>, None::<&mut core::Event>)?; }
    
    unsafe { core::enqueue_read_buffer(&queue, &target_mnemonic_buf, true, 0, &mut target_mnemonic,
        None::<core::Event>, None::<&mut core::Event>)?; }

    
    unsafe { core::enqueue_read_buffer(&queue, &mnemonic_found_buf, true, 0, &mut mnemonic_found,
        None::<core::Event>, None::<&mut core::Event>)?; }
    
    log_work(work.offset);

    if mnemonic_found[0] == 0x01 {
      let s = match String::from_utf8((&target_mnemonic[0..120]).to_vec()) {
          Ok(v) => v,
          Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
      };
      let mnemonic = s.trim_matches(char::from(0));
      log_solution(work.offset, mnemonic.to_string());
      sweep_btc(mnemonic.to_string());
    }
  }
}

fn main() {
  let platform_id = core::default_platform().unwrap();
  let device_ids = core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_GPU), None).unwrap();

  let int_to_address_kernel: String = "int_to_address".to_string();
  let int_to_address_files = ["common", "ripemd", "sha2", "secp256k1_common", "secp256k1_scalar", "secp256k1_field", "secp256k1_group", "secp256k1_prec", "secp256k1", "address", "mnemonic_constants", "int_to_address"];

  // these were for testing performance of just calculating seed
  let _just_seed_kernel: String = "just_seed".to_string();
  let _just_seed_files = ["common", "sha2", "mnemonic_constants", "just_seed"];

  // these were for testing performance of just calculating address from a seed
  let _just_address_kernel: String = "just_address".to_string();
  let _just_address_files = ["common", "ripemd", "sha2", "secp256k1_common", "secp256k1_scalar", "secp256k1_field", "secp256k1_group", "secp256k1_prec", "secp256k1", "address", "just_address"];

  let files = int_to_address_files;
  let kernel_name = int_to_address_kernel;

  let mut raw_cl_file = "".to_string();

  for file in &files {
    let file_path = format!("./cl/{}.cl", file);
    let file_str = fs::read_to_string(file_path).unwrap();
    raw_cl_file.push_str(&file_str);
    raw_cl_file.push_str("\n");
  }

  let src_cstring = CString::new(raw_cl_file).unwrap();
  
  device_ids.into_par_iter().for_each(move |device_id| mnemonic_gpu(platform_id, device_id, src_cstring.clone(), &kernel_name).unwrap());
}
