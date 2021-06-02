use super::EventProcessor;
use crate::{
    database::sled::SledEventDatabase,
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{event_data::EventData, sections::seal::LocationSeal},
    event_message::{parse::message, SignedEventMessage},
};
use crate::{
    event_message::{
        parse,
        parse::{signed_event_stream, signed_message, Deserialized},
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

    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)

    let icp_raw = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;
    let deserialized_icp = parse::signed_message(icp_raw).unwrap().1;

    let (id, _raw_parsed) = match &deserialized_icp {
        Deserialized::Event(e) => (e.event.event.event.prefix.clone(), e.event.raw.to_vec()),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(deserialized_icp)?.unwrap();

    // Check if processed event is in kel.
    let icp_from_db = event_processor.get_event_at_sn(&id, 0).unwrap().unwrap();
    assert_eq!(icp_from_db.event.serialize().unwrap(), icp_raw);

    let rot_raw = br#"{"v":"KERI10JSON000180_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"1","t":"rot","p":"ElIKmVhsgDtxLhFqsWPASdq9J2slLqG-Oiov0rEG4s-w","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"n":"EQpRYqbID2rW8X5lB6mOzDckJEIFae6NbJISXgJSN9qg","bt":"0","br":[],"ba":[],"a":[]}-AADAAOA7_2NfORAD7hnavnFDhIQ_1fX1zVjNzFLYLOqW4mLdmNlE4745-o75wtaPX1Reg27YP0lgrCFW_3Evz9ebNAQAB6CJhTEANFN8fAFEdxwbnllsUd3jBTZHeeR-KiYe0yjCdOhbEnTLKTpvwei9QsAP0z3xc6jKjUNJ6PoxNnmD7AQAC4YfEq1tZPteXlH2cLOMjOAxqygRgbDsFRvjEQCHQva1K4YsS3ErQjuKd5Z57Uac-aDaRjeH8KdSSDvtNshIyBw"#;
    let deserialized_rot = parse::signed_message(rot_raw).unwrap().1;

    let _raw_parsed = match &deserialized_rot {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process rotation event.
    event_processor.process(deserialized_rot.clone())?.unwrap();
    let rot_from_db = event_processor.get_event_at_sn(&id, 1).unwrap().unwrap();
    assert_eq!(rot_from_db.event.serialize().unwrap(), rot_raw);

    // Process the same rotation event one more time.
    let id_state = event_processor.process(deserialized_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventDuplicateError)));

    let ixn_raw = br#"{"v":"KERI10JSON000098_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"2","t":"ixn","p":"EFLtKYQZIoCFdSEjP7D5OgqElY2WwFB5vQD0Uvtp4RmI","a":[]}-AADAAip7QM2tvcyC4vbSX4A4avT03hHrJTTlkjQujOZRMroRL897wojcI4DIyxejOqsZcjrZHlU4S3RLYGmVbDEoPDgAB3NZj06_KCwxdTdIgCMETTHVJQa5AB8-dtqoD7ltaFIQxmC2K_ESp6DFLOrGQ2xTr97a-By1beM66YyBThjV8DQAC50owTQUxkyJ78vato0HuX9Edx-OxvBoepr61KknIfCjXKnlZrf-s_L0XFbz_0k8t3c9gmPkaI2vI-ZhzP31jBA"#;
    let deserialized_ixn = parse::signed_message(ixn_raw).unwrap().1;

    let _raw_parsed = match &deserialized_ixn {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process interaction event.
    event_processor.process(deserialized_ixn)?.unwrap();

    // Check if processed event is in db.
    let ixn_from_db = event_processor.get_event_at_sn(&id, 2).unwrap().unwrap();
    assert_eq!(ixn_from_db.event.serialize().unwrap(), ixn_raw);

    // Construct partially signed interaction event.
    let ixn_raw_2 = br#"{"v":"KERI10JSON000098_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"3","t":"ixn","p":"ElB_2LYB2i5wus2Dscnmc6e302HK-pgxLIe7iJhftzl0","a":[]}-AADAA18DLkJf2G--KOpRW2aD6ZAXR4koYdj0_OzEfDF5PFP3Y5vx8MSY3UwRBN97AT1pIkDVGqVbBg6nFi-0Bg5RTBQABZq5Kn6sML7NRTEyFKfyHez1YQJ4gzSqGsf1nyOxrXl5h0gwJllyNwTCzQhoyVT2fFAKtt9N_vaP9f90wB2ugCAACLsZcJWVrb1hL7EqL0wuzdtEJOSr-5-7EL0ae_nzvfCO6fw4q0PjgzCgFtoeDbAqUQbhzjfaybDwF9z9MVelWBg"#;
    let deserialized_ixn = parse::signed_message(ixn_raw_2).unwrap().1;
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
    let ixn_from_db = event_processor.get_event_at_sn(&id, 3);
    assert!(matches!(ixn_from_db, Ok(None)));

    // // Out of order event.
    let out_of_order_rot_raw = br#"{"v":"KERI10JSON000154_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"4","t":"rot","p":"EacZ-dpgav8rilfpmIDsTvH4vWzc9Tm_3p7Vxjmb7iG0","kt":"2","k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM","DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4","DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],"n":"","bt":"0","br":[],"ba":[],"a":[]}-AADAAt2KPgLzJvXorePSDjHLAStyJG9CakJuGau8QczgtdKPR3JHAOob5wPtTUJD2gHcZXH3wZ6ALM0mZSS6UdocsBwAB50HQHN2JHgj7dNfPQhqiDogbuT5WEx5Mi2Y5cefA6IHgrrQ3WSjZ3Bqai8t5vYfxg_xqcSRJTLkLRNSHZUzMCwACOMQNUmOXYHiHe9cxFie7Yr1y0lJ1tyQEbJnwa1Mr65LmnBIiVuGISDJXy74TZnv0PAnNCJF6TMtltX7nHf7LBw"#;
    let out_of_order_rot = parse::signed_message(out_of_order_rot_raw).unwrap().1;

    let id_state = event_processor.process(out_of_order_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventOutOfOrderError)));

    // Check if processed event is in kel. It shouldn't.
    let raw_from_db = event_processor.get_event_at_sn(&id, 4);
    assert!(matches!(raw_from_db, Ok(None)));

    let id: IdentifierPrefix = "EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8".parse()?;
    let mut kel = Vec::new();
    kel.extend(icp_raw);
    kel.extend(rot_raw);
    kel.extend(ixn_raw);

    let db_kel = event_processor.get_kerl(&id)?;

    assert_eq!(db_kel, Some(kel));

    Ok(())
}

#[test]
fn test_process_receipt() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);

    // Events and sigs are from keripy `test_direct_mode` test.
    // (keripy/tests/core/test_eventing.py#1855)
    // Parse and process controller's inception event.
    let icp_raw = br#"{"v":"KERI10JSON0000ed_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAvA7i3r6vs3ckxEZ2zVO8AtbjnaLKE_gwu0XNtzwB9p0fLKnC05cA07FWVx-mqoLDUO8mF1RcnoQvXWkVv_dtBA"#;
    let icp = parse::signed_message(icp_raw).unwrap().1;

    let controller_id_state = event_processor.process(icp)?;

    // Parse receipt of controller's inception event.
    let vrc_raw = br#"{"v":"KERI10JSON000091_","i":"EQf1hzB6s5saaQPdDAsEzSMEFoQx_WLsq93bjPu5wuqA","s":"0","t":"rct","d":"EXeKMHPw0ql8vHiBOpo72AOrOsWZ3bRDL-DKkYHo4v6w"}-FABED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM0AAAAAAAAAAAAAAAAAAAAAAAEeGqW24EnxUgO_wfuFo6GR_vii-RNv5iGo8ibUrhe6Z0-AABAAocy9m9ToxeeZk-FkgjFh1x839Ims4peTy2C5MdawIwoa9wlIDbD-wGmiGO4QdrQ1lSntqUAUMkcGAzB0Q6SsAA"#;
    let rcp = parse::signed_message(vrc_raw).unwrap().1;

    let id_state = event_processor.process(rcp.clone());
    // Validator not yet in db. Event should be escrowed.
    assert!(id_state.is_err());

    // Parse and process validator's inception event.
    let val_icp_raw = br#"{"v":"KERI10JSON0000ed_","i":"ED9EB3sA5u2vCPOEmX3d7bEyHiSh7Xi8fjew2KMl3FQM","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","bt":"0","b":[],"c":[],"a":[]}-AABAArFZxr-FnvQVZFX8WSipIxCGVCJjT6fj6qkZ-ei9UAGshPsqdX7scy0zNIB4_AfIjdSLLRWgL33AJmC2neaxuDg"#;
    let val_icp = parse::signed_message(val_icp_raw).unwrap().1;

    event_processor.process(val_icp)?;

    // Process receipt once again.
    let id_state = event_processor.process(rcp);
    assert!(id_state.is_ok());
    // Controller's state shouldn't change after processing receipt.
    assert_eq!(controller_id_state, id_state?);

    Ok(())
}

#[test]
fn test_process_delegated() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);

    let raw_parsed = |des| -> Result<Vec<u8>, Error> {
        match &des {
            Deserialized::Event(e) => Ok(e.event.raw.to_vec()),
            _ => Err(Error::SemanticError("bad deser".into()))?,
        }
    };

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py#62)
    let bobs_pref: IdentifierPrefix = "EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE".parse()?;

    let bobs_icp = br#"{"v":"KERI10JSON0000ed_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","s":"0","t":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAp8S6RgfLwdCEiz0jL9cXaDwTJF6MLuKyXp7EfJtrp2myOikOJVUB-w9UGZc1Y8dnURxhXPSca-ZEUAV73XOaAw"#;
    let msg = signed_message(bobs_icp).unwrap().1;
    event_processor.process(msg)?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON000121_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI"}-AABAA2_8Guj0Gf2JoNTq7hOs4u6eOOWhENALJWDfLxkVcS2uLh753FjtyE80lpeS3to1C9yvENyMnyN4q96ehA4exDA-GAB0AAAAAAAAAAAAAAAAAAAAAAQE3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII"#;
    let deserialized_dip = signed_message(dip_raw).unwrap().1;

    // Process dip event before delegating ixn event.
    let state = event_processor.process(deserialized_dip.clone());
    assert!(matches!(state, Err(Error::EventOutOfOrderError)));

    let child_prefix: IdentifierPrefix = "ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs".parse()?;

    // Check if processed dip is in kel.
    let dip_from_db = event_processor.get_event_at_sn(&child_prefix, 0);
    assert!(matches!(dip_from_db, Ok(None)));

    // Bob's ixn event with delegating event seal.
    let bobs_ixn = br#"{"v":"KERI10JSON000107_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","s":"1","t":"ixn","p":"E1-QL0TCdsBTRaKoakLjFhjSlELK60Vv8WdRaG6zMnTM","a":[{"i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"0","d":"E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHoPmY"}]}-AABAAROVSK0qK2gqlr_OUsnHNW_ksCyLVmRaysRne2dI5dweECGIy3_ZuFHyOofiDRt5tRE09PlS0uZdot6byFNr-AA'"#;
    let deserialized_ixn = signed_message(bobs_ixn).unwrap().1;
    event_processor.process(deserialized_ixn.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_processor
        .get_event_at_sn(&bobs_pref, 1)
        .unwrap()
        .unwrap();
    assert_eq!(
        ixn_from_db.event.serialize()?,
        raw_parsed(deserialized_ixn)?
    );

    // Process delegated inception event once again.
    event_processor.process(deserialized_dip.clone())?.unwrap();

    // Check if processed dip event is in db.
    let dip_from_db = event_processor.get_event_at_sn(&child_prefix, 0)?.unwrap();
    assert_eq!(
        dip_from_db.event.serialize()?,
        raw_parsed(deserialized_dip)?
    );

    // Bobs interaction event with delegated event seal.
    let bob_ixn = br#"{"v":"KERI10JSON000107_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","s":"2","t":"ixn","p":"E3fUycq1G-P1K1pL2OhvY6ZU-9otSa3hXiCcrxuhjyII","a":[{"i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"1","d":"EPjLBcb4pp-3PGvSi_fTvLvsqUqFoJ0CVCHvIFfu93Xc"}]}-AABAAclMVE-bkIn-wPiAqfgR384nWmslQHQvmo2o3xQvd_4Bt6bflc4BAmfBa03KgrDVqmB7qG2VXQbOHevkzOgRdD"#;
    let deserialized_ixn_drt = signed_message(bob_ixn).unwrap().1;

    // Delegated rotation event.
    let drt_raw = br#"{"v":"KERI10JSON000122_","i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"1","t":"drt","p":"E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHoPmY","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","br":[],"ba":[],"a":[]}-AABAAAVUMNfOl9Fcqx-C3fAYnaxvsiJJO3zG6rP0FQ2WVp__hMEaprrQbJL6-Esnny3U5zvMOqbso17rvecTwmVIwDw-GAB0AAAAAAAAAAAAAAAAAAAAAAgEbOI0OIIFv2VV5bmeSq1pwCn-6b2k6TdWcCbJHE6Ly7o"#;
    let deserialized_drt = signed_message(drt_raw).unwrap().1;

    // Process drt event before delegating ixn event.
    let child_state = event_processor.process(deserialized_drt.clone());
    assert!(matches!(child_state, Err(Error::EventOutOfOrderError)));

    // Check if processed drt is in kel.
    let drt_from_db = event_processor.get_event_at_sn(&child_prefix, 1);
    assert!(matches!(drt_from_db, Ok(None)));

    event_processor.process(deserialized_ixn_drt.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_processor.get_event_at_sn(&bobs_pref, 2)?.unwrap();
    assert_eq!(
        ixn_from_db.event.serialize()?,
        raw_parsed(deserialized_ixn_drt)?
    );

    // Process delegated rotation event once again.
    event_processor.process(deserialized_drt.clone())?.unwrap();

    // Check if processed drt event is in db.
    let drt_from_db = event_processor.get_event_at_sn(&child_prefix, 1)?.unwrap();
    assert_eq!(
        drt_from_db.event.serialize()?,
        raw_parsed(deserialized_drt)?
    );

    Ok(())
}

#[test]
fn test_validate_seal() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);

    // Process icp.
    let delegator_icp_raw = r#"{"v":"KERI10JSON0000e6_","i":"DcVUXDcB307nuuIlMGEUt9WZc4WF9W29IRvxDyVu6hyg","s":"0","t":"icp","kt":"1","k":["DcVUXDcB307nuuIlMGEUt9WZc4WF9W29IRvxDyVu6hyg"],"n":"E1_qFK5o1zYy5Os45Ot6niGC1ZpvQGNk1seLMBm80RZ0","wt":"0","w":[],"c":[]}-AABAANxCwp8L5f_8jLmdWSv8v-qNPv54m7Ij-Zlv5BMQZSs5AWuSaw96QkQt1DTOsDNgomLFuY8TdBeLdXjIIrqJWCw"#;
    let deserialized_icp = signed_message(delegator_icp_raw.as_bytes()).unwrap().1;
    event_processor.process(deserialized_icp.clone())?.unwrap();

    // Process delegating event.
    let delegating_event_raw = r#"{"v":"KERI10JSON000107_","i":"DcVUXDcB307nuuIlMGEUt9WZc4WF9W29IRvxDyVu6hyg","s":"1","t":"ixn","p":"E7rJVSh_MLTFcZ4v0urBxSJ103uR454Vo6St-wSCk_sI","a":[{"i":"EbuZO_Yr5Zt2Jvg0Sa96b2lDquGF3hHlhr7U7t3rLHvw","s":"0","d":"Eqid10S0HyiUI56hp2eBaS4pdnqvEnqV3p8f5DMfXX7w"}]}-AABAA1BOb5zF2PZ9x4GFpwVigVDTUAjpF1T3P23Z2uiwGej2J4EyoEvEW_WFxfVbyOLQW4eIWG2zNalOXy32sAL94BA"#;
    let deserialized_ixn = signed_message(delegating_event_raw.as_bytes()).unwrap().1;
    event_processor.process(deserialized_ixn.clone())?;

    // Get seal from delegated inception event.
    let dip_raw = r#"{"v":"KERI10JSON000165_","i":"EbuZO_Yr5Zt2Jvg0Sa96b2lDquGF3hHlhr7U7t3rLHvw","s":"0","t":"dip","kt":"1","k":["DEQbpbOD29I6igCqlxNYVy-TsFa8kmPKLdYscL0lxsPE"],"n":"Ey6FhAzq0Ivj8E-NYjxkWrlj6mLFL67S6ADcsxMhX46s","wt":"0","w":[],"c":[],"da":{"i":"DcVUXDcB307nuuIlMGEUt9WZc4WF9W29IRvxDyVu6hyg","s":"1","t":"ixn","p":"HiQ3FpdUUTT8DyNJWIcN18OouhiA6SfjcajsBVDHVMeY"}}"#;
    let deserialized_dip = message(dip_raw.as_bytes()).unwrap().1;
    let seal = if let EventData::Dip(dip) = deserialized_dip.event.event.event_data {
        dip.seal
    } else {
        LocationSeal::default()
    };

    if let Deserialized::Event(ev) = deserialized_ixn.clone() {
        if let EventData::Ixn(ixn) = ev.event.event.event.event_data {
            assert_eq!(
                ixn.previous_event_hash.derivation,
                SelfAddressing::Blake3_256
            );
            assert_eq!(seal.prior_digest.derivation, SelfAddressing::SHA3_256);
            assert_ne!(
                ixn.previous_event_hash.derivation,
                seal.prior_digest.derivation
            );
        }
    };

    assert!(event_processor
        .validate_seal(seal, dip_raw.as_bytes())
        .is_ok());

    Ok(())
}

#[test]
fn test_compute_state_at_sn() -> Result<(), Error> {
    use crate::event::sections::seal::EventSeal;
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);

    let kerl_str = br#"{"v":"KERI10JSON0000ed_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"0","t":"icp","kt":"1","k":["DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk"],"n":"EGofBtQtAeDMOO3AA4QM0OHxKyGQQ1l2HzBOtrKDnD-o","bt":"0","b":[],"c":[],"a":[]}-AABAAxemWo-mppcRkiGSOXpVwh8CYeTSEJ-a0HDrCkE-TKJ-_76GX-iD7s4sbZ7j5fdfvOuTNyuFw3a797gwpnJ-NAg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"1","t":"rot","p":"EvZY9w3fS1h98tJeysdNQqT70XLLec4oso8kIYjfu2Ks","kt":"1","k":["DLqde_jCw-C3y0fTvXMXX5W7QB0188bMvXVkRcedgTwY"],"n":"EW5MfLjWGOUCIV1tQLKNBu_WFifVK7ksthNDoHP89oOc","bt":"0","br":[],"ba":[],"a":[]}-AABAAuQcoYU04XYzJxOPp4cxmvXbqVpGADfQWqPOzo1S6MajUl1sEWEL1Ry30jNXaV3-izvHRNROYtPm2LIuIimIFDg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"2","t":"rot","p":"EOi_KYKjP4hinuTfgtoYj5QBw_Q1ZrRtWFQDp0qsNuks","kt":"1","k":["De5pKs8wiP9bplyjspW9L62PEANoad-5Kum1uAllRxPY"],"n":"ERKagV0hID1gqZceLsOV3s7MjcoRmCaps2bPBHvVQPEQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAPKIYNAm6nmz4cv37nvn5XMKRVzfKkVpJwMDt2DG-DqTJRCP8ehCeyDFJTdtvdJHjKqrnxE4Lfpll3iUzuQM4Aw{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"3","t":"rot","p":"EVK1FbLl7yWTxOzPwk7vo_pQG5AumFoeSE51KapaEymc","kt":"1","k":["D2M5V_e23Pa0IAqqhNDKzZX0kRIMkJyW8_M-gT_Kw9sc"],"n":"EYJkIfnCYcMFVIEi-hMMIjBQfXcTqH_lGIIqMw4LaeOE","bt":"0","br":[],"ba":[],"a":[]}-AABAAsrKFTSuA6tEzqV0C7fEbeiERLdZpStZMCTvgDvzNMfa_Tn26ejFRZ_rDmovoo8xh0dH7SdMQ5B_FvwCx9E98Aw{"v":"KERI10JSON000098_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"4","t":"ixn","p":"EY7VDg-9Gixr9rgH2VyWGvnnoebgTyT9oieHZIaiv2UA","a":[]}-AABAAqHtncya5PNnwSbMRegftJc1y8E4tMZwajVVj2-FmGmp82b2A7pY1vr7cv36m7wPRV5Dusf4BRa5moMlHUpSqDA"#;
    // Process kerl
    signed_event_stream(kerl_str)
        .unwrap()
        .1
        .into_iter()
        .for_each(|event| {
            event_processor.process(event.clone()).unwrap();
        });

    let event_seal = EventSeal {
        prefix: "DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk".parse()?,
        sn: 2,
        event_digest: "EVK1FbLl7yWTxOzPwk7vo_pQG5AumFoeSE51KapaEymc".parse()?,
    };

    let state_at_sn = event_processor
        .compute_state_at_sn(&event_seal.prefix, event_seal.sn)?
        .unwrap();
    assert_eq!(state_at_sn.sn, event_seal.sn);
    assert_eq!(state_at_sn.prefix, event_seal.prefix);
    let ev_dig = event_seal.event_digest.derivation.derive(&state_at_sn.last);
    assert_eq!(event_seal.event_digest, ev_dig);

    Ok(())
}

#[test]
fn test_escrow_trans_receipt() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);

    let receipted_icp_raw = r#"{"v":"KERI10JSON00014b_","i":"Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8","s":"0","t":"icp","kt":"1","k":["DyVl2PmD3sasa7Dua5D0kYI4TKWHqrxJ3T56GygrbEVo","D23TFwtUxx0g6s6PZ_Y105MRA1zguhVvT3pHvNBm0eKI","Dl762uk9FDMKmbI9L9OaWJ0pZ4jQI9Anw_Idf-1j96E0"],"n":"EmvbCD2xJCLVVX5tPKx1Sx4fkJH9lxK3UPLfaz2uBcK8","bt":"0","b":[],"c":[],"a":[]}-AADAAtxQVTmnIuryIzoJCeG6FP0hXf9VBeYcPKK-oXQR5DuWPEPrvubI8uC1FpPqGBZr5h02OlizPeTTKGntUkuzsDgABlVnLnOz69hjJGWrqFZBC7QKxRjvRuQ1W1VxeZIVtqJ--5B4RsiFLiv5CPChY6_qHYHw8q5PdsAO8JUIMq5zABgACNN6aGP8ucfeAAxBgFjOVgOjQeSt-SBj7EaANZL7IeBCnWX-txKGu4AuHkAj543DjjwVjEYhHxoHL5kNnKiajCQ"#;
    let deserialized_icp = signed_message(receipted_icp_raw.as_bytes()).unwrap().1;

    let receipt_raw = r#"{"v":"KERI10JSON000091_","i":"Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8","s":"0","t":"rct","d":"EYlNEtEjHGdtRWBqGKEplUdZZeYZkaqnJX4v6X3wcYW4"}-FABEp1GZvfUnuPhOBMLQPXFmkOebDlL7kJNA1HkSipJJxQg0AAAAAAAAAAAAAAAAAAAAAAAExFmxTfgEofzzcRf8vTKqWscddHH2-lgdawQA-KQj0qo-AADAAPiK37BGm6QUhgbHKsiRGZ3AcIPirZ7RODeP7BRJ8VzYfHjTW_BfBxB8rNO2U3d3XUKbgMx2AzYZ9l9akcpEZDwABC4yB7vROuKGJB-AI0fiCYvUqSpfiVksMvDCkd0S90WZp7ITkhrm6At5DTlLQPNx4Tgx1VOY1_1LyE7jxu1xQCgACMkFdzCBwKF4_wx3KncbFrhDyTH5izvyrP4mdQL4kX__ck65zn5lkcnmEhw5VnwqJ0hbTWyjhRO_Aj96um1hlCQ"#;
    let deserialized_rct = signed_message(receipt_raw.as_bytes()).unwrap().1;

    let validator_icp = r#"{"v":"KERI10JSON00014b_","i":"Ep1GZvfUnuPhOBMLQPXFmkOebDlL7kJNA1HkSipJJxQg","s":"0","t":"icp","kt":"1","k":["DhZmbp0Gho0hr_GLUQZc20kpNNeCDJDIMhhLppqWMEdw","D4wt4AOt_GjhlGCn-1_I1_Lu8xsMD7offgheWEeAmMWw","DljvHsCaxADsqx-AtZmmuYJMCIK3ughSVhWOoDEETBvE"],"n":"Er-WtzG1t5_TrQ30u18DKvpVSdjaX_8LzdspR63RnwmA","bt":"0","b":[],"c":[],"a":[]}-AADAAKcdrOKvfbqmhQWuJSgOkDA6ldPBRqQdI3AD7bHljRN7aMAIIbT648VUszgVwnIFceSEFqFuTekBO_y-DgJwsAAABvuLOR3qEg1jlBksNWNzYmQq39pikWXOY4hPYM6mAA0qrn7yY7429eA82KBA_CWO9cbB1nupXwS_uZjakhKjADgACxRSVmN01paGWRLRiOv2rApYaBaobOlQSBmfXXzfEv9zd8cua_hmcVS5TT6WIez147wegmGxf1ZzY56XEoGMnAg"#;
    let deserialized_val_icp = signed_message(validator_icp.as_bytes()).unwrap().1;

    // Recepter (the one who made event) prefix
    let pref: IdentifierPrefix = "Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8".parse()?;

    // Receipt message should be escrowed, because there is neither validator pref nor recepter pref in db.
    let state = event_processor.process(deserialized_rct.clone());
    assert!(state.is_err());
    // Check if it is in receipts.
    let trans_receipts = event_processor.db.get_receipts_t(&pref);
    assert!(matches!(trans_receipts, None));

    // Check if it is in escrow.
    let esc = event_processor.db.get_escrow_t_receipts(&pref).unwrap();
    assert_eq!(esc.count(), 1);

    // Recepter's ixn:
    let ixn_raw = br#"{"v":"KERI10JSON000098_","i":"Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8","s":"1","t":"ixn","p":"EYlNEtEjHGdtRWBqGKEplUdZZeYZkaqnJX4v6X3wcYW4","a":[]}-AADAAPGLwK1HzVU2-PkTlCDaRJJOoqwvcG8uGxq7soFkcjLNs4ox995IDpiJN7R4scau7j2ukvsZekqhv42tTYTzPAAABZVOI5WsAFzxH0xjiuZj_A5Q3Uls7UEZKjGCRS3jGSaHCiqNHiGxKO9kf2dQ3ugVpzP5ptRQGDIMqnuLfEw8UAwAC4zaP5SZ-g_oDxTac0OqrNZ47klR2vafwou8GSlLX2dXpLFOyDzD150BbbykaNNIADAR-rxDXNlbzbjMa9InLBw"#;
    let deserialized_ixn = signed_message(ixn_raw).unwrap().1;

    // Validator's rot:
    let validator_rot_raw = br#"{"v":"KERI10JSON000180_","i":"Ep1GZvfUnuPhOBMLQPXFmkOebDlL7kJNA1HkSipJJxQg","s":"1","t":"rot","p":"ExFmxTfgEofzzcRf8vTKqWscddHH2-lgdawQA-KQj0qo","kt":"1","k":["DfGz_Jdwm7ljrT8xR8MyPIspIFlBavorgPf-pd45gqvM","D84sztcgyr19nHJM8aBEDEe8IfMU8JyStnJgcgNT1URM","DOIBNK4GstnZ4866As94LKs7L4_FnpB5YWccoY0Om8cE"],"n":"Ets4P5L4tYBXo2C3g-GeHwkhBZbL_kMF_aYai28iXHHc","bt":"0","br":[],"ba":[],"a":[]}-AADAAVBzUfnc9gDigsh5kxGkIc4g9ebO1F8SRCS4qVn_Of4iPLkvrDcpanP4Dno1MYs1ZHKsaxWooiEYwe-NbhliECgABpGbP7jrWTauQD_q4JpyNdCf-Bi54SIkIuv-SBEbKUIuXMw2LcmG07uAPIhi06GRDD_6GJo-wltRlKL3WJJ1VCQACITX9C9kFHs-b0Bzqi5LQKGcWYZJHuWX85Du6DiTJ86_UyeeG8dx1EuFAVkzTiW4eOK_pllSrhLwTxBljyxotDQ"#;
    let deserialized_val_rot = signed_message(validator_rot_raw).unwrap().1;

    // Signed receipt of ixn:
    let receipt_ixn_raw = br#"{"v":"KERI10JSON000091_","i":"Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8","s":"1","t":"rct","d":"Es9Y7SujBNBgTu3FO8cwGahDqMsz8J0yo0U_X89pMRes"}-FABEp1GZvfUnuPhOBMLQPXFmkOebDlL7kJNA1HkSipJJxQg0AAAAAAAAAAAAAAAAAAAAAAQE5PVpebKFwhAAqArUyYeM2vi1iJrXbhPQtcZp-WSNpeY-AADAAZOzX8q9DdMD9mKolWk-u_Yx4o8pldEyou5Bwdh-zL2UoHNa8mttNQQ7hJX8BXTXjLyYojU_2iakv5mfMaATQCwABfNX6I0eyFVfURCnypK6QZpSroklVQ-IfAdmFkDK0aCYXpfmuU6m922UkA-vpEhRLEgtwFdOzA5YAhJiemFwiDwAC5Y3PWeIUc4gGIx_cUbm-b29j2gjAgWkAupRIDnYOmnxt2fH_BvJ479gBf1HzgiPMYf8lEXZKiiwRU1VQaM5CBw"#;
    let deserialized_ixn_rct = signed_message(receipt_ixn_raw).unwrap().1;

    // Receipt message should be escrowed, because there is neither validator pref nor recepter pref in db.
    let state = event_processor.process(deserialized_ixn_rct);
    assert!(state.is_err());
    // Check if it is in receipts.
    let trans_receipts = event_processor.db.get_receipts_t(&pref);
    assert!(matches!(trans_receipts, None));

    // Check if it is in escrow.
    let esc = event_processor.db.get_escrow_t_receipts(&pref).unwrap();
    assert_eq!(esc.count(), 2);

    // Receptor's rot:
    let rot_raw = br#"{"v":"KERI10JSON000180_","i":"Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8","s":"2","t":"rot","p":"Es9Y7SujBNBgTu3FO8cwGahDqMsz8J0yo0U_X89pMRes","kt":"1","k":["D5B8KSGWb__uNJMPMciNk5FBz-sgaRimja0tuPmUfs0o","DcxtFVilB-Ei4D0wbzSHq9_rBvsCdWvfpjkPsc2r2FN0","DAlrozT3JzoA9xd3YN-w16nQYXnk5jp1hMNWXUbo2NtI"],"n":"EkQMjUHUTzWSL8aCbS-kC6UOXiwJeNWKwpngM0sjlL6g","bt":"0","br":[],"ba":[],"a":[]}-AADAAyuk-YthqgUIZw8BJXYHliG2U-HOyIh2qYhpUXnbMDtjRX71kyjXhTtOw5SN-36bdaA6LmaOPuKevmVUI5L4pBAABecn61ol49ilAGK6lfPVKKcDfcPFir0q6cTlc2RERAUY3xFTgR5iSAmbCqEF11vtXa_7wX6Hotu49YCSSPNUHAQACziP1JLEiIU_Cgea9ljRNuzwMiCF_QW0NgxLb3m3mt24RTqisC99Jgv0boxiKWyqqzEnj6dbiHq6YzTaF23kdDg"#;
    let deserialized_rot = signed_message(rot_raw).unwrap().1;

    // Signed receipt of rot:
    let receipt_rot_raw = br#"{"v":"KERI10JSON000091_","i":"Ew6zD07kTItS-jsaXb4dfDiZuRzKVdLPn2vt0lxyRfO8","s":"2","t":"rct","d":"EQnwRD64gFSecMxSFvMKFsDO2pGl9HUprcAdAERq8bns"}-FABEp1GZvfUnuPhOBMLQPXFmkOebDlL7kJNA1HkSipJJxQg0AAAAAAAAAAAAAAAAAAAAAAQE5PVpebKFwhAAqArUyYeM2vi1iJrXbhPQtcZp-WSNpeY-AADAAQRVTrgeHdfyszSG1BZZrFN0BKmnl6jJN3qfCgeeOw3c53XLoLmyz3uqHQ0EHubQnLUq_CEBnZC4LuiZW9X3cBwABRICFglr10L_mZ2UZCQf8JbMgR_nNje_mvzeCYRUlOzeqh5tZis3rYElCEBtiEZ9dOXgKgChrfhF1FbHUYF5wBgACyLARatvJqjXYBPpeHz2QDNDYHui0s1sqaYvPktsMhsmP7m1eoEC_jS5lvCq-U237ybvV4Urs_20YoF7vtlVIDQ"#;
    let deserialized_rot_rct = signed_message(receipt_rot_raw).unwrap().1;

    // Receipt message should be escrowed, because there is neither validator pref nor recepter pref in db.
    let state = event_processor.process(deserialized_rot_rct);
    assert!(state.is_err());
    // Check if it is in receipts.
    let trans_receipts = event_processor.db.get_receipts_t(&pref);
    assert!(matches!(trans_receipts, None));

    // Check the escrow.
    let esc = event_processor.db.get_escrow_t_receipts(&pref).unwrap();
    assert_eq!(esc.count(), 3);

    // Process receiptor's events.
    event_processor.process(deserialized_icp)?;
    event_processor.process(deserialized_ixn)?;
    event_processor.process(deserialized_rot)?;

    event_processor.process_transferable_receipts_escrow(&pref, 0)?;
    event_processor.process_transferable_receipts_escrow(&pref, 1)?;
    event_processor.process_transferable_receipts_escrow(&pref, 2)?;

    // Check if it is in escrow. All receipts still should be there because there is no validator events in db yet.
    let esc = event_processor.db.get_escrow_t_receipts(&pref).unwrap();
    assert_eq!(esc.count(), 3);

    // Process validateor inception event and process escrow again.
    event_processor.process(deserialized_val_icp)?;
    event_processor.process_transferable_receipts_escrow(&pref, 0)?;
    event_processor.process_transferable_receipts_escrow(&pref, 1)?;
    event_processor.process_transferable_receipts_escrow(&pref, 2)?;

    // Check if receipts are still in escrow. One of them should be processed successfully..
    let esc = event_processor.db.get_escrow_t_receipts(&pref).unwrap();
    assert_eq!(esc.count(), 2);

    // Check if any receipt is in receipts.
    let trans_receipts = event_processor.db.get_receipts_t(&pref);
    assert!(matches!(trans_receipts, Some(_)));
    assert_eq!(trans_receipts.unwrap().count(), 1);

    // Process validator rotation event and process escrows again.
    event_processor.process(deserialized_val_rot)?;
    event_processor.process_transferable_receipts_escrow(&pref, 1)?;
    event_processor.process_transferable_receipts_escrow(&pref, 2)?;

    // Check if receipts are still in escrow. All of them shoud be processed successfully.
    let esc = event_processor.db.get_escrow_t_receipts(&pref).unwrap();
    assert_eq!(esc.count(), 0);

    // Check if any receipt is in receipts. All of them should be there.
    let trans_receipts = event_processor.db.get_receipts_t(&pref);
    assert!(matches!(trans_receipts, Some(_)));
    assert_eq!(trans_receipts.unwrap().count(), 3);

    Ok(())
}

#[test]
pub fn test_process_outoforder_escrow() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = SledEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(&db);
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)
    let icp_raw = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;
    let deserialized_icp = parse::signed_message(icp_raw).unwrap().1;

    let rot_raw = br#"{"v":"KERI10JSON000180_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"1","t":"rot","p":"ElIKmVhsgDtxLhFqsWPASdq9J2slLqG-Oiov0rEG4s-w","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"n":"EQpRYqbID2rW8X5lB6mOzDckJEIFae6NbJISXgJSN9qg","bt":"0","br":[],"ba":[],"a":[]}-AADAAOA7_2NfORAD7hnavnFDhIQ_1fX1zVjNzFLYLOqW4mLdmNlE4745-o75wtaPX1Reg27YP0lgrCFW_3Evz9ebNAQAB6CJhTEANFN8fAFEdxwbnllsUd3jBTZHeeR-KiYe0yjCdOhbEnTLKTpvwei9QsAP0z3xc6jKjUNJ6PoxNnmD7AQAC4YfEq1tZPteXlH2cLOMjOAxqygRgbDsFRvjEQCHQva1K4YsS3ErQjuKd5Z57Uac-aDaRjeH8KdSSDvtNshIyBw"#;
    let deserialized_rot = parse::signed_message(rot_raw).unwrap().1;

    let ixn_raw = br#"{"v":"KERI10JSON000098_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"2","t":"ixn","p":"EFLtKYQZIoCFdSEjP7D5OgqElY2WwFB5vQD0Uvtp4RmI","a":[]}-AADAAip7QM2tvcyC4vbSX4A4avT03hHrJTTlkjQujOZRMroRL897wojcI4DIyxejOqsZcjrZHlU4S3RLYGmVbDEoPDgAB3NZj06_KCwxdTdIgCMETTHVJQa5AB8-dtqoD7ltaFIQxmC2K_ESp6DFLOrGQ2xTr97a-By1beM66YyBThjV8DQAC50owTQUxkyJ78vato0HuX9Edx-OxvBoepr61KknIfCjXKnlZrf-s_L0XFbz_0k8t3c9gmPkaI2vI-ZhzP31jBA"#;
    let deserialized_ixn = parse::signed_message(ixn_raw).unwrap().1;
    
    let id = match &deserialized_icp {
        Deserialized::Event(e) => e.event.event.event.prefix.clone(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };
    // Process ixn. It is out of order event.
    let state = event_processor.process(deserialized_ixn.clone());
    assert!(matches!(state, Err(Error::EventOutOfOrderError)));

    let outoforder: Vec<SignedEventMessage> = event_processor
        .db
        .get_outoforder_events(&id)
        .unwrap()
        .map(|e| e.into())
        .collect();
    assert_eq!(outoforder.len(), 1);

    // Process the same ixn to check if escrowing is idepotent.
    // TODO it's not. Fix it.
    // let state = event_processor.process(deserialized_ixn);
    // let outoforder: Vec<SignedEventMessage> = event_processor
    //     .db
    //     .get_outoforder_events(&id)
    //     .unwrap()
    //     .map(|e| e.into())
    //     .collect();
    // assert_eq!(outoforder.len(), 1);

    // Process out of order escrow. Check if is change anything in escrow.
    event_processor.process_outoforder_escrow(&id, 2)?;
    let outoforder: Vec<_> = event_processor
        .db
        .get_outoforder_events(&id)
        .unwrap()
        .collect();
    assert_eq!(outoforder.len(), 1);

    // Process rot. It should be esrowed as out of order.
    let state = event_processor.process(deserialized_rot);
    assert!(matches!(state, Err(Error::EventOutOfOrderError)));
    let outoforder: Vec<_> = event_processor
        .db
        .get_outoforder_events(&id)
        .unwrap()
        .collect();
    assert_eq!(outoforder.len(), 2);

    // Process out of order escrow. Check if is change anything in escrow.
    event_processor.process_outoforder_escrow(&id, 1)?;
    event_processor.process_outoforder_escrow(&id, 2)?;
    let outoforder: Vec<_> = event_processor
        .db
        .get_outoforder_events(&id)
        .unwrap()
        .collect();
    assert_eq!(outoforder.len(), 2);

    // Process icp event and out of order events then.
    event_processor.process(deserialized_icp)?;
    event_processor.process_outoforder_escrow(&id, 1)?;
    event_processor.process_outoforder_escrow(&id, 2)?;

    // Check if escrowed event was processed succesfully.
    let outoforder: Vec<_> = event_processor
    .db
    .get_outoforder_events(&id)
    .unwrap()
    .collect();
    assert_eq!(outoforder.len(), 0);

    Ok(())
}
