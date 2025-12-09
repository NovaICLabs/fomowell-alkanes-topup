use candid::{CandidType, Deserialize, Principal};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use ic_cdk::{api::caller, storage};

pub type AlkaneKey = String;

#[derive(Clone, CandidType, Deserialize, Debug)]
pub struct AlkaneRecord {
    pub txid: String,
    pub vout: u64,
    pub send_address: String,
    pub alkaneid: String,
    pub amount: u64,
}

pub type BatchAlkaneData = AlkaneRecord;

#[derive(Clone, CandidType, Deserialize, Debug)]
pub struct AlkaneUtxoRecord {
    pub amount: u64,
    pub txid: String,
    pub vout: u64,
    pub satoshi: u64,
}

pub type AlkaneUtxoKey = String;


thread_local! {
    static OWNER: RefCell<Principal> = RefCell::new(Principal::anonymous());
    static ALKANE_DATA: RefCell<HashMap<AlkaneKey, AlkaneRecord>> = RefCell::new(HashMap::new());
    static WHITE_TOKEN_LIST: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    static TOKEN_ID_MAP: RefCell<HashMap<String, u64>> = RefCell::new(HashMap::new());
    static ALKANE_UTXO_LEDGER: RefCell<HashMap<AlkaneUtxoKey, AlkaneUtxoRecord>> = RefCell::new(HashMap::new());
}

pub fn init(initial_owner: Principal) {
    OWNER.with(|o| *o.borrow_mut() = initial_owner);
}

pub fn is_authorized() -> bool {
    caller() == OWNER.with(|o| *o.borrow())
}

pub fn set_owner(new_owner: Principal) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    OWNER.with(|o| *o.borrow_mut() = new_owner);
    Ok("Set Admain successfully".into())
}



pub fn add_white_token(token: String) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    WHITE_TOKEN_LIST.with(|set| {
        set.borrow_mut().insert(token.clone());
    });

    Ok(format!("Token `{}` added to whitelist.", token))
}

pub fn remove_white_token(token: String) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    WHITE_TOKEN_LIST.with(|set| {
        set.borrow_mut().remove(&token);
    });

    Ok(format!("Token `{}` removed from whitelist.", token))
}

pub fn is_white_token(token: String) -> bool {
    WHITE_TOKEN_LIST.with(|set| set.borrow().contains(&token))
}

pub fn get_white_tokens() -> Vec<String> {
    WHITE_TOKEN_LIST.with(|set| set.borrow().iter().cloned().collect())
}

pub fn set_token_id_mapping(alkaneid: String, meme_token_id: u64) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    TOKEN_ID_MAP.with(|map| {
        map.borrow_mut().insert(alkaneid.clone(), meme_token_id);
    });

    Ok(format!("Token ID mapping set: {} -> {}", alkaneid, meme_token_id))
}


pub fn get_token_id_by_alkaneid(alkaneid: String) -> Result<u64, String> {
    TOKEN_ID_MAP.with(|map| {
        map.borrow()
            .get(&alkaneid)
            .copied()
            .ok_or_else(|| format!("Token ID not found for alkaneid: {}", alkaneid))
    })
}

fn make_utxo_key(address: &str, alkaneid: &str) -> AlkaneUtxoKey {
    format!("{}:{}", address, alkaneid)
}

pub fn set_utxo(address: String, alkaneid: String, utxo: AlkaneUtxoRecord) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    let key = make_utxo_key(&address, &alkaneid);
    ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow_mut().insert(key.clone(), utxo);
    });

    Ok(format!("UTXO set for address: {}, alkaneid: {}", address, alkaneid))
}

pub fn get_alkane_fund_utxo(address: String, alkaneid: String) -> Result<AlkaneUtxoRecord, String> {
    let key = make_utxo_key(&address, &alkaneid);
    ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow()
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("UTXO not found for address: {}, alkaneid: {}", address, alkaneid))
    })
}

pub fn remove_utxo(address: String, alkaneid: String) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    let key = make_utxo_key(&address, &alkaneid);
    ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow_mut().remove(&key);
    });

    Ok(format!("UTXO removed for address: {}, alkaneid: {}", address, alkaneid))
}



pub fn get_utxos_by_address(address: String) -> Vec<(String, String, AlkaneUtxoRecord)> {
    ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow()
            .iter()
            .filter(|(key, _)| key.starts_with(&format!("{}:", address)))
            .map(|(key, value)| {
                let parts: Vec<&str> = key.split(':').collect();
                let addr = parts.get(0).unwrap_or(&"").to_string();
                let alkaneid = parts.get(1).unwrap_or(&"").to_string();
                (addr, alkaneid, value.clone())
            })
            .collect()
    })
}

pub fn get_utxos_by_alkaneid(alkaneid: String) -> Vec<(String, AlkaneUtxoRecord)> {
    ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow()
            .iter()
            .filter(|(key, _)| key.ends_with(&format!(":{}", alkaneid)))
            .map(|(key, value)| {
                // 从键中提取地址
                let address = key.split(':').next().unwrap_or("").to_string();
                (address, value.clone())
            })
            .collect()
    })
}

pub fn get_all_utxos() -> Vec<(String, String, AlkaneUtxoRecord)> {
    ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow()
            .iter()
            .map(|(key, value)| {
                let parts: Vec<&str> = key.split(':').collect();
                let address = parts.get(0).unwrap_or(&"").to_string();
                let alkaneid = parts.get(1).unwrap_or(&"").to_string();
                (address, alkaneid, value.clone())
            })
            .collect()
    })
}




pub fn utxo_count() -> u64 {
    ALKANE_UTXO_LEDGER.with(|ledger| ledger.borrow().len() as u64)
}


pub fn batch_upload(batch: Vec<BatchAlkaneData>) -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    let mut uploaded = 0;

    ALKANE_DATA.with(|db| {
        let mut map = db.borrow_mut();
        for item in batch {
            let key = item.txid.clone();
            map.insert(key, item);
            uploaded += 1;
        }
    });

    Ok(format!("Batch upload successful: {} items saved", uploaded))
}

pub fn alkanes_query(txid: String) -> Result<AlkaneRecord, String> {
    let key = txid;

    ALKANE_DATA.with(|db| {
        db.borrow()
            .get(&key)
            .cloned()
            .ok_or_else(|| "Record not found".into())
    })
}

pub fn get_all() -> Vec<AlkaneRecord> {
    ALKANE_DATA.with(|db| db.borrow().values().cloned().collect())
}

pub fn count() -> u64 {
    ALKANE_DATA.with(|db| db.borrow().len() as u64)
}

pub fn clear() -> Result<String, String> {
    if !is_authorized() {
        return Err("Unauthorized".into());
    }

    ALKANE_DATA.with(|db| db.borrow_mut().clear());
    WHITE_TOKEN_LIST.with(|set| set.borrow_mut().clear());
    TOKEN_ID_MAP.with(|map| map.borrow_mut().clear());
    ALKANE_UTXO_LEDGER.with(|ledger| ledger.borrow_mut().clear());

    Ok("All data cleared".into())
}

pub fn pre_upgrade() {
    let state_data: Vec<(AlkaneKey, AlkaneRecord)> = ALKANE_DATA.with(|db| {
        db.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    });

    let whitelist: Vec<String> = WHITE_TOKEN_LIST.with(|set| set.borrow().iter().cloned().collect());
    
    let token_id_map: Vec<(String, u64)> = TOKEN_ID_MAP.with(|map| {
        map.borrow().iter().map(|(k, v)| (k.clone(), *v)).collect()
    });

    let utxo_ledger: Vec<(AlkaneUtxoKey, AlkaneUtxoRecord)> = ALKANE_UTXO_LEDGER.with(|ledger| {
        ledger.borrow().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    });

    storage::stable_save((state_data, whitelist, token_id_map, utxo_ledger, OWNER.with(|o| *o.borrow()))).unwrap();
}



pub fn post_upgrade() {
    if let Ok((data, whitelist, token_id_map, utxo_ledger, owner)) =
        storage::stable_restore::<(Vec<(AlkaneKey, AlkaneRecord)>, Vec<String>, Vec<(String, u64)>, Vec<(AlkaneUtxoKey, AlkaneUtxoRecord)>, Principal)>()
    {
        OWNER.with(|o| *o.borrow_mut() = owner);

        ALKANE_DATA.with(|db| {
            let mut map = db.borrow_mut();
            map.clear();
            for (k, v) in data {
                map.insert(k, v);
            }
        });

        WHITE_TOKEN_LIST.with(|set| {
            let mut whitelist_set = set.borrow_mut();
            whitelist_set.clear();
            for token in whitelist {
                whitelist_set.insert(token);
            }
        });
        
        TOKEN_ID_MAP.with(|map| {
            let mut token_map = map.borrow_mut();
            token_map.clear();
            for (k, v) in token_id_map {
                token_map.insert(k, v);
            }
        });

        ALKANE_UTXO_LEDGER.with(|ledger| {
            let mut utxo_map = ledger.borrow_mut();
            utxo_map.clear();
            for (k, v) in utxo_ledger {
                utxo_map.insert(k, v);
            }
        });
    }
}
