mod pb;
use std::{fmt::Display, io::Write};

use pb::mydata::v1 as mydata;

use sha3::{Digest, Keccak256};
use substreams::{hex, scalar::BigInt, Hex};
use substreams_ethereum::{block_view::CallView, pb::eth::v2::Block};

#[allow(unused_imports)]
use num_traits::cast::ToPrimitive;

substreams_ethereum::init!();

const TX_HASH: [u8; 32] = hex!("b440503a5ffbcb5bd2df6dc4321446c702dbfd25d1eda8add327b6796fd4858c");
const TRANSFER_TOPIC: [u8; 32] =
    hex!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

// Inferred by looking at `call[2].keccak_preimages` and taking the preimages that specify twice the same slot
// which is usually the correctly slot. This is dynamic based on the layout of the variables in the Solidity contract
// so great care must be taken to ensure that the correct slot is used.
//
// There is also a way to infer the right slot using heuristics, finding the keccak preimages that are the same
const MAPPING_SLOT: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000066");

#[substreams::handlers::map]
fn map_my_data(blk: Block) -> Option<mydata::MyData> {
    if blk.number != 12130763 {
        return None;
    }

    substreams::log::info!("Found block: {:?}", blk.number);
    for tx in &blk.transaction_traces {
        if tx.hash != TX_HASH {
            continue;
        }

        substreams::log::info!("Found transaction: {:?}", Hex(&tx.hash));
        tx.logs_with_calls().for_each(|(log_view, call_view)| {
            if log_view.topics.len() == 3 && log_view.topics[0] == TRANSFER_TOPIC {
                substreams::log::info!("Found transfer, extracting associated balance change");

                // One can infer the MAPPING_SLOT value by iterating on the list of keccak_preimages
                // and finding 2 preimages that are 64 bytes long, and is of the form `<from>:<slot>`
                // and `<to>:<slot>` where `<slot>` must be the same.
                // call_view.call.keccak_preimages.iter().for_each(|preimage| {});

                // Here I used the topic directly because it's an address but encoded over 20 bytes
                // just like how the storage slot is encoded which is:
                //
                // keccak256(32bytes(address) + 32bytes(slot))
                //
                // Where `bytes32` ensure that the element is 32 bytes long (padded with zeros if necessary)
                // and `+` is the concatenation operator so the final address in our example above has
                // 64 bytes.
                let from_storage_slot = storage_slot(&log_view.topics[1], &MAPPING_SLOT);
                let to_storage_slot = storage_slot(&log_view.topics[2], &MAPPING_SLOT);

                substreams::log::info!(
                    "Storage slot (From: {:x}, To: {:x})",
                    Hex(&from_storage_slot),
                    Hex(&to_storage_slot)
                );

                if let Some(change) = find_balance_change(&from_storage_slot, &call_view) {
                    substreams::log::info!(
                        "Found storage change 'from' balance change {}",
                        &change
                    );
                }

                if let Some(change) = find_balance_change(&to_storage_slot, &call_view) {
                    substreams::log::info!(
                        "Found storage change for 'to' balance change {}",
                        &change
                    );
                }
            }
        });

        return Some(mydata::MyData::default());
    }

    None
}

struct BalanceChange {
    old: BigInt,
    new: BigInt,
}

impl Display for BalanceChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.old, self.new)
    }
}

fn find_balance_change(storage_slot: &[u8; 32], call_view: &CallView<'_>) -> Option<BalanceChange> {
    call_view
        .call
        .storage_changes
        .iter()
        .find(|storage_change| storage_change.key == storage_slot)
        .map(|storage_change| BalanceChange {
            old: BigInt::from_unsigned_bytes_be(&storage_change.old_value),
            new: BigInt::from_unsigned_bytes_be(&storage_change.new_value),
        })
}

fn storage_slot(address: &[u8], slot: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak256::new();
    keccak.write(address).expect("write of address failed");
    keccak.write(slot).expect("write of slot failed");

    keccak.finalize().into()
}
