use super::EventProcessor;
use crate::{database::lmdb::LmdbEventDatabase, database::EventDatabase, error::Error};
use crate::{
    event_message::{
        parse,
        parse::{signed_message, Deserialized},
    },
    prefix::IdentifierPrefix,
};
use std::fs;

#[test]
fn test_process() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = LmdbEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(db);

    let icp_raw = r#"{"vs":"KERI10JSON000159_","pre":"EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CIxq7QGP_dEQiwc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","toad":"0","wits":[],"cnfg":[]}-AADAAh_trqX993WCZfZ2Mm8Rj2AnlpJzStsv2x4M3gKOIpA740SCYGTDIU4L2Zokd8Krfakt98vy2vAYTjrJ7_UMnBQABNgYwwmeinupnrK8nIbVkz4iL7OgjAalNSNimZciYLCBRoKD5jbyXbHDxgycjl2vaw3roAzuaSi4686OY4P0kDgACbz0tl-U_EBbSfdKmtJHkSNfbDjB7pw_k9C9MuTv1eP3XM4OFApLJyhshWDtWmUzb4uorpXWvqRKfkMIRCKyBDQ"#;
    // Create deserialized inception event from string.
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    let deserialized_icp = parse::signed_message(icp_raw.as_bytes()).unwrap().1;

    let (id, raw_parsed) = match &deserialized_icp {
        Deserialized::Event(e) => (e.event.event.event.prefix.clone(), e.event.raw.to_vec()),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    let id_state = event_processor.process(deserialized_icp)?.unwrap();

    assert_eq!(id_state.sn, 0);
    // Check if processed event is in kel.
    let icp_from_db = event_processor.db.last_event_at_sn(&id, 0).unwrap();
    assert_eq!(icp_from_db, Some(raw_parsed));

    let rot_raw = r#"{"vs":"KERI10JSON000198_","pre":"EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CIxq7QGP_dEQiwc","sn":"1","ilk":"rot","dig":"EYmBZ0_Nn4sjid4UcQckAq_IXE6yzyh0Yy-lwKeRUVxg","sith":"2","keys":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"nxt":"EQpRYqbID2rW8X5lB6mOzDckJEIFae6NbJISXgJSN9qg","toad":"0","cuts":[],"adds":[],"data":[]}-AADAAtjBE4-kz5byJJDJuqKKKyjujw0CBMJfdx4XPmky_7cl8jNyeoTpcSbcifr7LUbuM_iQIBXFNIBqL9KMw8RQgAQABB8zTUrCwrBzO4M58oJ_CRu6fdVXK-jy5tYSwoqWcxjtRYnF-OIZ03zVjdhiky24-P_dRCGBQE-VmOQcSRW6NAgACrt7M9UM2Thvib1OhFcQtGjNnDNkG502_YWUnhOYOiS-_poEQRHi2PrF5FSNSv8cnAKgTH9UNt8h98kqOqXYJCQ"#;
    // Create deserialized rotation event.
    let deserialized_rot = parse::signed_message(rot_raw.as_bytes()).unwrap().1;

    let raw_parsed = match &deserialized_rot {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process rotation event.
    let id_state = event_processor.process(deserialized_rot.clone())?.unwrap();
    assert_eq!(id_state.sn, 1);

    // Check if processed event is in db.
    let rot_from_db = event_processor.db.last_event_at_sn(&id, 1).unwrap();
    assert_eq!(rot_from_db, Some(raw_parsed));

    // Process the same rotation event one more time.
    let id_state = event_processor.process(deserialized_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventDuplicateError)));

    let ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CIxq7QGP_dEQiwc","sn":"2","ilk":"ixn","dig":"EkH8Pm-Fv6QDawC4rDulf6X9anQ_AETbNdUh4HCjB0Co","data":[]}-AADAAYbN7F_JmSY9dZ5QzaccH8uaO6iCARwgebv4aw-MmM69Cn6iDWncWoK_Deu-Ik3hMTPpyhkUPsh444-psVFrhCAAB_YnGFnNbwJPiO1__3ecxOxFLBgvoAmSJ3j6ojA_a6tTbp19x0hg38OFvDlytbkbAXBCQPGrLDKoTclhFZ5guAQACpVhXP2WGe_Gd2aVpStB1NdRo9ipFFto4jyMeMWorUdCMMMwwTuIBa_gw62f4OyDTfWv4kSZo47l2li2RT6ydAw"#;
    // Create deserialized interaction event.
    let deserialized_ixn = parse::signed_message(ixn_raw.as_bytes()).unwrap().1;

    let raw_parsed = match &deserialized_ixn {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process interaction event.
    let id_state = event_processor.process(deserialized_ixn)?.unwrap();
    assert_eq!(id_state.sn, 2);

    // Check if processed event is in db.
    let ixn_from_db = event_processor.db.last_event_at_sn(&id, 2).unwrap();
    assert_eq!(ixn_from_db, Some(raw_parsed));

    // Construct partially signed interaction event.
    let ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CIxq7QGP_dEQiwc","sn":"3","ilk":"ixn","dig":"EI8Y-mZzPFiY-RF7Pzvk11TP70op_xmX_8_X4ja01yPM","data":[]}-AADAAzyIUY_RJ_eXuPBor1a7bbiInTBntqMJLbzDzsTAfIHc3HB7SJThLKh2Oozkm38LIBrJF2xMXx5jjM70EQNZ4CgABNy-Ct5NW7W6W0347Uw8PMrQYpNVTT3DfgsfXMva2iVnYLzw9mQedhGILf1dsW2LIk5bvoQYBCCsVf6N16j-xAgACDaYuZa_09xZFgotKblT2BPuMETl9b73y6R7-LEe9jAE47RUAWeOFp6654Du1zB78UnM2jjKMrqMhG_q0BaD4Ag"#;
    let deserialized_ixn = parse::signed_message(ixn_raw.as_bytes()).unwrap().1;
    // Make event partially signed.
    let partially_signed_deserialized_ixn = match deserialized_ixn {
        Deserialized::Event(mut e) => {
            let sigs = e.signatures[1].clone();
            e.signatures = vec![sigs];
            Deserialized::Event(e)
        }
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process partially signed interaction event.
    let id_state = event_processor.process(partially_signed_deserialized_ixn);
    assert!(matches!(id_state, Err(Error::NotEnoughSigsError)));

    // Check if processed ixn event is in kel. It shouldn't because of not enough signatures.
    let ixn_from_db = event_processor.db.last_event_at_sn(&id, 3);
    assert!(matches!(ixn_from_db, Ok(None)));

    // Out of order event.
    let out_of_order_ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"EUEtw_3JqBhrLtwwlP9QLnDXZGjJ3CIxq7QGP_dEQiwc","sn":"4","ilk":"ixn","dig":"EI8Y-mZzPFiY-RF7Pzvk11TP70op_xmX_8_X4ja01yPM","data":[]}-AADAAzyIUY_RJ_eXuPBor1a7bbiInTBntqMJLbzDzsTAfIHc3HB7SJThLKh2Oozkm38LIBrJF2xMXx5jjM70EQNZ4CgABNy-Ct5NW7W6W0347Uw8PMrQYpNVTT3DfgsfXMva2iVnYLzw9mQedhGILf1dsW2LIk5bvoQYBCCsVf6N16j-xAgACDaYuZa_09xZFgotKblT2BPuMETl9b73y6R7-LEe9jAE47RUAWeOFp6654Du1zB78UnM2jjKMrqMhG_q0BaD4Ag"#;

    let out_of_order_ixn = parse::signed_message(out_of_order_ixn_raw.as_bytes())
        .unwrap()
        .1;

    let id_state = event_processor.process(out_of_order_ixn);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventOutOfOrderError)));

    // Check if processed event is in kel. It shouldn't.
    let ixn_from_db = event_processor.db.last_event_at_sn(&id, 4);
    assert!(matches!(ixn_from_db, Ok(None)));

    Ok(())
}

#[test]
fn test_process_receipt() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = LmdbEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(db);

    // Events and sigs are from keripy `test_direct_mode` test.
    // Construct and process controller's inception event.
    let icp_raw = r#"{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABAApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOvVjHpdZlty3Hgk6ilF8pVpAQ"#;
    let icp = parse::signed_message(icp_raw.as_bytes()).unwrap().1;

    let controller_id_state = event_processor.process(icp)?;

    // Construct receipt of controller's inception event.
    let vrc_raw = r#"{"vs":"KERI10JSON00010c_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG70m6LIjkiCdoI","sn":"0","ilk":"vrc","dig":"EdpkS5j6xIAnPFjovQKLaou1jF7XcLny-pYZde4p35jc","seal":{"pre":"E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0M","dig":"Es0RthuviC_p-qHut_JCfMKSFwpljZ-WoppazqZIid-A"}}-AABAAcQJDHTzG8k1WYCR6LahLCIlcDED21Slz66piD9tcZo4VEmyWHYDccj4aRvVdy9xHqHsn38FMGN26x4S2skJGCw"#;
    let rcp = parse::signed_message(vrc_raw.as_bytes()).unwrap().1;

    let id_state = event_processor.process(rcp.clone());
    // Validator not yet in db. Event should be escrowed.
    assert!(id_state.is_err());

    // Contruct and process validator's inception event.
    let val_icp_raw = r#"{"vs":"KERI10JSON0000fb_","pre":"E0uTVILY2KXdcxX40MSM9Fr8EpGwfjMNap6ulAAzVt0M","sn":"0","ilk":"icp","sith":"1","keys":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"nxt":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","toad":"0","wits":[],"cnfg":[]}-AABAAR5dawnJxU_Gbb8EK2xUMLb2AU7wLlZDHlDzHvovP-YIowqFq719VMQc9hrEwW9JKs90leAm2rUp3_DOi7-olBg"#;
    let val_icp = parse::signed_message(val_icp_raw.as_bytes()).unwrap().1;

    event_processor.process(val_icp)?;

    // Process receipt once again.
    let id_state = event_processor.process(rcp);
    assert!(id_state.is_ok());
    // Controller's state shouldn't change after processing receipt.
    assert_eq!(controller_id_state, id_state?);

    Ok(())
}

#[test]
fn test_delegation() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = LmdbEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(db);

    // Prepare bob's key event log. Process inception event.
    let bobs_icp = r#"{"vs":"KERI10JSON0000fb_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"0","ilk":"icp","sith":"1","keys":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"nxt":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","toad":"0","wits":[],"cnfg":[]}-AABAA_-vC5z6_KnT2iWrA8-twdgh-BfjrWTlq8VN0sj6uQEyoE4zgoCive3x6GGvr1HjKHwpFRoXnsDsXanQV3QB0BQ"#;
    let msg = signed_message(bobs_icp.as_bytes()).unwrap().1;
    event_processor.process(msg)?;

    // Bobs interaction event with delegated event seal.
    let bobs_ixn = r#"{"vs":"KERI10JSON00010e_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"1","ilk":"ixn","dig":"Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ","data":[{"pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE","dig":"EeBPcw30IVCylYANEGOg3V8f4nBYMspEpqNaq2Y8_knw"}]}-AABAA8_fyED6L-y6d8GUg1nKCMtfhyChd_6_bpfAXv1nMC76lzpyaPBTm0O6geoO9kBuaaBCz3ojPUDAtktikVRFlCA"#;
    let delegating_msg = signed_message(bobs_ixn.as_bytes()).unwrap().1;

    let bobs_pref: IdentifierPrefix = "EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U".parse()?;

    // Delegated inception event.
    let dip_raw = r#"{"vs":"KERI10JSON000183_","pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE","sn":"0","ilk":"dip","sith":"1","keys":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"nxt":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","toad":"0","wits":[],"cnfg":[],"seal":{"pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"1","ilk":"ixn","dig":"Ey-05xXgtfYvKyMGa-dladxUQyXv4JaPg-gaKuXLfceQ"}}-AABAAMSF33ZiOLYH7Pg74MnMQjbfT_oq9wDeFy4ztfEWP0VagIKPqgYW_zrAkyJrZnQ-7-bfpekNtyRh3sN4doFseAg"#;
    let delegated_msg = signed_message(dip_raw.as_bytes()).unwrap().1;

    let child_prefix: IdentifierPrefix = "Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE".parse()?;

    // Process dip event before delegating ixn event.
    let child_state = event_processor.process(delegated_msg.clone());
    assert!(matches!(child_state, Err(Error::EventOutOfOrderError)));

    // Check if processed dip is in kel.
    let dip_from_db = event_processor.db.last_event_at_sn(&child_prefix, 0);
    assert!(matches!(dip_from_db, Ok(None)));

    event_processor.process(delegating_msg)?;

    let child_state = event_processor.process(delegated_msg.clone())?.unwrap();

    assert_eq!(child_state.sn, 0);
    assert_eq!(child_state.prefix, child_prefix);
    assert_eq!(
        child_state.last,
        match delegated_msg {
            Deserialized::Event(e) => e.event.event.serialize()?,
            _ => vec![],
        }
    );
    assert_eq!(child_state.delegator, Some(bobs_pref));

    // Bobs interaction event with delegated event seal.
    let bob_ixn = r#"{"vs":"KERI10JSON00010e_","pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"2","ilk":"ixn","dig":"Eews7edyNg7fa-bze0UcCSCG4vitUo6dB5DetsoZA2NU","data":[{"pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE","dig":"EeiCC5kb8Ms2-T3lnx83kwEPq_iJBBL0QC03ab559Dts"}]}-AABAA3V9qL1YINRBkSvkj-Q-NyMQoWpprrK05mrUYQNuc1EoPAt9pBa8quPorxhB-Q0_DVAd5PI6zH9Wn5j0R_eZQDw"#;
    let delegating_msg = signed_message(bob_ixn.as_bytes()).unwrap().1;

    // Delegated rotation event.
    let drt_raw = r#"{"vs":"KERI10JSON0001c2_","pre":"Ek7M173EvQZ6kLjyorCwZK4XWwyNcSi6u7lz5-M6MyFE","sn":"1","ilk":"drt","dig":"EeBPcw30IVCylYANEGOg3V8f4nBYMspEpqNaq2Y8_knw","sith":"1","keys":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"nxt":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","toad":"0","cuts":[],"adds":[],"data":[],"seal":{"pre":"EXmV-FiCyD7U76DoXSQoHlG30hFLD2cuYWEQPp0mEu1U","sn":"2","ilk":"ixn","dig":"Eews7edyNg7fa-bze0UcCSCG4vitUo6dB5DetsoZA2NU"}}-AABAAXRILNpCj1-oLVbl4ZLSkNZTDDDudEVqk2nHxA--lNhacAI1P_5-uAjlr93cmy2WDXZA61ddtF7mI5SjRMnSqDA"#;
    let delegated_msg = signed_message(drt_raw.as_bytes()).unwrap().1;

    // Process drt event before delegating ixn event.
    let child_state = event_processor.process(delegated_msg.clone());
    assert!(matches!(child_state, Err(Error::EventOutOfOrderError)));

    // Check if processed drt is in kel.
    let drt_from_db = event_processor.db.last_event_at_sn(&child_prefix, 1);
    assert!(matches!(drt_from_db, Ok(None)));

    event_processor.process(delegating_msg)?;

    let child_state = event_processor.process(delegated_msg.clone())?.unwrap();
    assert_eq!(child_state.sn, 1);
    assert_eq!(child_state.prefix, child_prefix);
    assert_eq!(
        child_state.last,
        match delegated_msg {
            Deserialized::Event(e) => e.event.event.serialize()?,
            _ => vec![],
        }
    );

    Ok(())
}
