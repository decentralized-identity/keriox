use super::EventProcessor;
use crate::event_message::{parse, parse::Deserialized};
use crate::{database::lmdb::LmdbEventDatabase, database::EventDatabase, error::Error};
use std::fs;

#[test]
fn test_process() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = LmdbEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(db);

    let icp_raw = r#"{"vs":"KERI10JSON000159_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"0","ilk":"icp","sith":"2","keys":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"nxt":"Evhf3437ZRRnVhT0zOxo_rBX_GxpGoAnLuzrVlDK8ZdM","toad":"0","wits":[],"cnfg":[]}-AADAAJ66nrRaNjltE31FZ4mELVGUMc_XOqOAOXZQjZCEAvbeJQ8r3AnccIe1aepMwgoQUeFdIIQLeEDcH8veLdud_DQABTQYtYWKh3ScYij7MOZz3oA6ZXdIDLRrv0ObeSb4oc6LYrR1LfkICfXiYDnp90tAdvaJX5siCLjSD3vfEM9ADDAACQTgUl4zF6U8hfDy8wwUva-HCAiS8LQuP7elKAHqgS8qtqv5hEj3aTjwE91UtgAX2oCgaw98BCYSeT5AuY1SpDA"#;
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

    let rot_raw = r#"{"vs":"KERI10JSON000198_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"1","ilk":"rot","dig":"EF9THPxXUribmjC641JsDJynFJwieRTpDn-xvhxvXaPI","sith":"2","keys":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"nxt":"EwkvQoCtKlgZeQK1eUb8BfmaCLCVVC13jI-j-g7Qt5KY","toad":"0","cuts":[],"adds":[],"data":[]}-AADAAuEZp7-BaPscSZkKR-xFGbRj-vq5DQJBp5Fm9RKc1glep_2md7gMrGbEdJC3b2hGa_j-fyEFA_gze-ugRwYLCCwABDoHupcc04lamZcZb3gm-3vpwA7VyIWolKOSmGfm9PRt1uh8mu--Cj4RQzo2mlY3s-GLlYKY_DK1SbZ5lOCUbDwACCSgi9afM9B01aoMbYfSBNXnFsT5FiIM_g3mRvr8yOa6sItd4Issj8fZgZtkprGGxreXsbqKiEHim4pAWTdNWCg"#;
    let deserialized_rot = parse::signed_message(rot_raw.as_bytes()).unwrap().1;

    // Create deserialized rotation event.
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

    let ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"2","ilk":"ixn","dig":"E0d-mZATnsQJcsbMftEZTxckCOBpSO8HVZHBBNTg2P9Q","data":[]}-AADAAriQOdH87Tv5Axbhk1fgDXgXWv1oAGyxaW-0de6Z3CtRGDpfJgquxFhYROi7Fa-AHf8OXfaeLObcUS03xNSlOCQABb8fE50SRZkSfqlFZoGOkusCl_ed3JLt1kr22KnYnUC63ykNjpyAVJpmFISo7McV8QAr10xrYzSY5C6xbgJGnAwACAmnpfoxmrR9xhX61nn-oYtuJ_iNiotDKKdAHRK8Qm87GcGF6M9RcFD7XFci7czpsXLMHXnH5mM8WXpW4FDuYCw"#;

    // Construct partially signed interaction event.
    let deserialized_ixn = parse::signed_message(ixn_raw.as_bytes()).unwrap().1;

    let raw_parsed = match &deserialized_ixn {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process interaction event.
    let id_state = event_processor.process(deserialized_ixn);
    assert!(matches!(id_state, Err(Error::NotEnoughSigsError)));

    // Check if processed ixn event is in kel. It shouldn't because of not enough signatures.
    let ixn_from_db = event_processor.db.last_event_at_sn(&id, 2);
    assert!(matches!(ixn_from_db, Ok(None)));

    // Out of order event.
    let out_of_order_ixn_raw = r#"{"vs":"KERI10JSON0000a3_","pre":"ECui-E44CqN2U7uffCikRCp_YKLkPrA4jsTZ_A0XRLzc","sn":"5","ilk":"ixn","dig":"EwiIGwOHz-mXTM9q7UHjILuj2rs3GESAbrLJiZP1u-ug","data":[]}-AADAA5WWCK-bVduSseQBSRsDoy0LeXk8VcZXZGawUTYYkcTrkdYIxSXHecUvAHoOdGN1H0QJXuQJEAkLlEN1Y7g_1CwAB1e-eIsZTdyKGLMBI_Aig3-pf3l5BmUyi12coRusyExZoMcO5SSokaeZgRMZRb6ncDk7iSRylaKeq5iBhmDmGBwACOdWDJWMh1EHvco3ndqwBhJBkoT6PcYJenls6xcNuB9yHbkGuZPuhHMAYHRD60sBxTbrEf28AvAW60sZPYl_JAA"#;

    let out_of_order_ixn = parse::signed_message(ixn_raw.as_bytes()).unwrap().1;

    let id_state = event_processor.process(out_of_order_ixn);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventOutOfOrderError)));

    // Check if processed event is in kel. It shouldn't.
    let ixn_from_db = event_processor.db.last_event_at_sn(&id, 5);

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
