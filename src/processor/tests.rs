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
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)

    let icp_raw = br#"{"v":"KERI10JSON000144_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4YeUSqBv5sEk","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","wt":"0","w":[],"c":[]}-AADAA74a3kHBjpaY2h3AzX8UursaGoW8kKU1rRLlMTYffMvKSTbhHHy96brGN2P6ehcmEW2nlUNZVuMf8zo6Qd8PkCgABIJfoSJejaDh1g-UZKkldxtTCwic7kB3s15EsDPKpm_6EhGcxVTt0AFXQUQMroKgKrGnxL0GP6gwEdmdu9dVRAgACtJFQBQiRX5iqWpJQntfAZTx6VIv_Ghydg1oB0QCq7s8D8LuKH5n1S5t8AbbQPXv6Paf7AVJRFv8lhCT5cdx3Bg"#;
    let deserialized_icp = parse::signed_message(icp_raw).unwrap().1;

    let (id, raw_parsed) = match &deserialized_icp {
        Deserialized::Event(e) => (e.event.event.event.prefix.clone(), e.event.raw.to_vec()),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(deserialized_icp)?.unwrap();

    // Check if processed event is in kel.
    let icp_from_db = event_processor.db.last_event_at_sn(&id, 0).unwrap();
    assert_eq!(icp_from_db, Some(raw_parsed));

    let rot_raw = br#"{"v":"KERI10JSON000180_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4YeUSqBv5sEk","s":"1","t":"rot","p":"EBI6frz8AI-glGeV60vAaSAiI5mxGFWUeyzADKYHzaPU","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"n":"EQpRYqbID2rW8X5lB6mOzDckJEIFae6NbJISXgJSN9qg","wt":"0","wr":[],"wa":[],"a":[]}-AADAAC-daSxzSMhp4Sptp_3RLfOjK04Gi7beE7luKrZmT1QoCdsMq6n2XZ5X_V8FoC7U16tLESDVY3wMrIkq8kzFnBwABSNp89up9bg97gmVgCx-Hkumjh8h9bOBlyoPk0pD2e0EuaKGdP9prsvsnD8UzFgqynlIjkvJY9CNX4Yta09CDBQACnU4KEpqLqSTuGyphlcgSCwBF-8tnKKyEt2_ROONJiD5Pod8nJVMfj-OvAqkyXGTu53YAXz-B984ndAnPWzrVAg"#;
    let deserialized_rot = parse::signed_message(rot_raw).unwrap().1;

    let raw_parsed = match &deserialized_rot {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process rotation event.
    event_processor.process(deserialized_rot.clone())?.unwrap();
    let rot_from_db = event_processor.db.last_event_at_sn(&id, 1).unwrap();
    assert_eq!(rot_from_db, Some(raw_parsed.clone()));

    // Process the same rotation event one more time.
    let id_state = event_processor.process(deserialized_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventDuplicateError)));

    let ixn_raw = br#"{"v":"KERI10JSON000098_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4YeUSqBv5sEk","s":"2","t":"ixn","p":"EH4SWmiiDBa9pN89Hg9EXXaccYkBYiTB_lnjo_bmVfjY","a":[]}-AADAAliN9WXT4t2bSliF19e1MN7sj3mU13c_DtHfumAunfo4u5_-X_7rFN4FZBMeb7QuXioWFki7qzf4VAr94hxN4BAABK2yFgdhLCiGaFjFjXEuwS6oSuRom3EXLQM1dNVwBbVYEoYlGK9FT8vXJ-nb_eo26xPoMAbvq364zT7HFP_PiCAACBc-Ck4fnPNi-JDNHE8TpPkutyRZ0bJ1cdadui3lbuw2-dgACtWwMH5viiR83djYdzKjCZtKpIz7o31hL39tmAw"#;
    let deserialized_ixn = parse::signed_message(ixn_raw).unwrap().1;

    let raw_parsed = match &deserialized_ixn {
        Deserialized::Event(e) => e.event.raw.to_vec(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process interaction event.
    event_processor.process(deserialized_ixn)?.unwrap();

    // Check if processed event is in db.
    let ixn_from_db = event_processor.db.last_event_at_sn(&id, 2).unwrap();
    assert_eq!(ixn_from_db, Some(raw_parsed));

    // Construct partially signed interaction event.
    let ixn_raw = br#"{"v":"KERI10JSON000098_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4YeUSqBv5sEk","s":"3","t":"ixn","p":"EpAHPuE6SqPw_oodA7utfEUxFh2pL6iYJ7Uwy1UQqi08","a":[]}-AADAAsMWMYvI8ymFUmdwiOSBqS16nOSYT70xKMztFprjdpDQC4VGsOcChyd9XsCqu_UId0H2-gbesX-ql3skh-qf0DwABVVVWbOMbnO8gn4EOAiY9wrGP7Q1uh8a-WUyPYlaii3iQ2Qucu_kzznl7MgnKeH2c7m_3h7HfoebC5wngg5-SAQACiau2633rcR8zTlvCMq4tQL2BpPMV61FgAU-9RVvBsbSkEs00mxwoxN_Xz4nqUaCX9bR8t9Mx3mgABXemOeTMAQ"#;
    let deserialized_ixn = parse::signed_message(ixn_raw).unwrap().1;
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
    let out_of_order_rot_raw = br#"{"v":"KERI10JSON000154_","i":"EJPRBUSEdUuZnh9kRGg8y7uBJDxTGZdp4YeUSqBv5sEk","s":"4","t":"rot","p":"E1-rI18gS9qOinFpkbhlLOjOh_V8Sy90qIU_xfd-OxWk","kt":"2","k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM","DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4","DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],"n":"","wt":"0","wr":[],"wa":[],"a":[]}-AADAAt2REL9QiIbO71AiYh4R4tpuG5mDTViVmvOesmAxG29UIB_FZT-vMPUpM1k52CwU-yB_YI_zneruJuDdMzTUhDAABHZyt_gu_6pql52HnLVCmu6mCPzH3D8GkMW1cAykkUtve32A6Xz31cMrABl8AJMQTK_fCchp_qwsisbR-1Un1BAACGoJ1eRTTwyLzeoXegQgqseEv3JREFYWGEuiB-LVSlb0-L1aTegUIop6wos0uZltsAqmt3zNA-AMxIkXF8qhLDg"#;
    let out_of_order_rot = parse::signed_message(out_of_order_rot_raw).unwrap().1;

    let id_state = event_processor.process(out_of_order_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventOutOfOrderError)));

    // Check if processed event is in kel. It shouldn't.
    let raw_from_db = event_processor.db.last_event_at_sn(&id, 4);
    assert!(matches!(raw_from_db, Ok(None)));

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
    // (keripy/tests/core/test_eventing.py#1855)
    // Parse and process controller's inception event.
    let icp_raw = br#"{"v":"KERI10JSON0000e6_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAmDoPp9jDio1hznNDO-3T2KA_FUbY8f_qybT6_FqPAuf89e9AMDXP5wch6jvT4Ev4QRp8HqtTb9t2Y6_KJPYlBw"#;
    let icp = parse::signed_message(icp_raw).unwrap().1;

    let controller_id_state = event_processor.process(icp)?;

    // Parse receipt of controller's inception event.
    let vrc_raw = br#"{"v":"KERI10JSON000105_","i":"EH7Oq9oxCgYa-nnNLvwhp9sFZpALILlRYyB-6n4WDi7w","s":"0","t":"vrc","d":"EEnwxEm5Bg5s5aTLsgQCNpubIYzwlvMwZIzdOM0Z3u7o","a":{"i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","d":"EGFSGYH2BjtKwX1osO0ZvLw98nuuo3lMkveRoPIJzupo"}}-AABAAb6S-RXeAqUKl8UuNwYpiaFARhMj-95elxmr7uNU8m7buVSPVLbTWcQYfI_04HoP_A_fvlU_b099fiEJyDSA2Cg"#;
    let rcp = parse::signed_message(vrc_raw).unwrap().1;

    let id_state = event_processor.process(rcp.clone());
    // Validator not yet in db. Event should be escrowed.
    assert!(id_state.is_err());

    // Parse and process validator's inception event.
    let val_icp_raw = br#"{"v":"KERI10JSON0000e6_","i":"EpDA1n-WiBA0A8YOqnKrB-wWQYYC49i5zY_qrIZIicQg","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","wt":"0","w":[],"c":[]}-AABAAll_W0_FsjUyJnYokSNPqq7xdwIBs0ebq2eUez6RKNB-UG_y6fD0e6fb_nANvmNCWjsoFjWv3XP3ApXUabMgyBA"#;
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
    let db = LmdbEventDatabase::new(root.path()).unwrap();
    let event_processor = EventProcessor::new(db);

    let raw_parsed = |des| -> Result<Vec<u8>, Error> {
        match &des {
            Deserialized::Event(e) => Ok(e.event.raw.to_vec()),
            _ => Err(Error::SemanticError("bad deser".into()))?,
        }
    };

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py#62)
    let bobs_pref: IdentifierPrefix = "EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE".parse()?;

    let bobs_icp = br#"{"v":"KERI10JSON0000e6_","i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE","s":"0","t":"icp","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","wt":"0","w":[],"c":[]}-AABAAQPFdtnncXLz6dE6A-tXGYYK0BHu3I3Pj-G8DxlbzC3yx5MV8yucZILqAA5toZNODnHVHZtPIMkDknqldL4utBQ"#;
    let msg = signed_message(bobs_icp).unwrap().1;
    event_processor.process(msg)?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON000165_","i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs","s":"0","t":"dip","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","wt":"0","w":[],"c":[],"da":{"i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE","s":"1","t":"ixn","p":"EvP2kWxEjTMI3auc6x64EpU-nMQZHiBeKeuavcGdRB24"}}-AABAADv-a3LeXEStuY1LHknepuJ7mBcTByugqQ1TNRMrIa0rctfjKsh-hkkkpwDj6M_OLLaFtLqBpmdNTUgBPANLzCQ"#;
    let deserialized_dip = signed_message(dip_raw).unwrap().1;

    // Process dip event before delegating ixn event.
    let state = event_processor.process(deserialized_dip.clone());
    assert!(matches!(state, Err(Error::EventOutOfOrderError)));

    let child_prefix: IdentifierPrefix = "ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs".parse()?;

    // Check if processed dip is in kel.
    let dip_from_db = event_processor.db.last_event_at_sn(&child_prefix, 0);
    assert!(matches!(dip_from_db, Ok(None)));

    // Bob's ixn event with delegating event seal.
    let bobs_ixn = br#"{"v":"KERI10JSON000107_","i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE","s":"1","t":"ixn","p":"EvP2kWxEjTMI3auc6x64EpU-nMQZHiBeKeuavcGdRB24","a":[{"i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs","s":"0","d":"ESDuaqpoI8-HLD8-eLijUMZpXqYFkNArJFDvt3ABYr9I"}]}-AABAAZ4V2cSIXYEPg5BtkJSHVBj-A0dGI6rH2XGaVt1kewqGeJjpy4uzObPWnoBpaEojFa5AnrUJEgMytORoWMqEhCw"#;
    let deserialized_ixn = signed_message(bobs_ixn).unwrap().1;
    event_processor.process(deserialized_ixn.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_processor.db.last_event_at_sn(&bobs_pref, 1).unwrap();
    assert_eq!(ixn_from_db, Some(raw_parsed(deserialized_ixn)?));

    // Process delegated inception event once again.
    event_processor.process(deserialized_dip.clone())?.unwrap();

    // Check if processed dip event is in db.
    let dip_from_db = event_processor
        .db
        .last_event_at_sn(&child_prefix, 0)
        .unwrap();
    assert_eq!(dip_from_db, Some(raw_parsed(deserialized_dip)?));

    // Bobs interaction event with delegated event seal.
    let bob_ixn = br#"{"v":"KERI10JSON000107_","i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE","s":"2","t":"ixn","p":"EtzXPztLsGC5DGyooSdHdBGIOHjhblBWtZ_AOhGS-hDE","a":[{"i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs","s":"1","d":"E-dZsWLp2IIPVDbGdGS-yvuw4HeV_w_w76FHsofmuiq0"}]}-AABAAmloDxOwz6ztvRR_4N8Hn-6ZJk6_0nQhfNE7bzX6NpJRfYDwmUw3rXod0g46iFOLqEWw12oaFVzVH85NYAh67Ag"#;
    let deserialized_ixn_drt = signed_message(bob_ixn).unwrap().1;

    // Delegated rotation event.
    let drt_raw = br#"{"v":"KERI10JSON0001a1_","i":"ErLe2qWp4VCmDp7v_R01tC-ha13ZEZY0VGcgYtPRhqPs","s":"1","t":"drt","p":"ESDuaqpoI8-HLD8-eLijUMZpXqYFkNArJFDvt3ABYr9I","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","wt":"0","wr":[],"wa":[],"a":[],"da":{"i":"EiBlVttjqvySMbA4ShN19rSrz3D0ioNW-Uj92Ri7XnFE","s":"2","t":"ixn","p":"EtzXPztLsGC5DGyooSdHdBGIOHjhblBWtZ_AOhGS-hDE"}}-AABAAXcUl6KlY4VOx8ZumFMc0uR4iHBGmPQo4IAx0nIiiEDB_u2ewkvgIDIp1ELDGxfc2VVUkl38Z7PqwydBdpIK0DA"#;
    let deserialized_drt = signed_message(drt_raw).unwrap().1;

    // Process drt event before delegating ixn event.
    let child_state = event_processor.process(deserialized_drt.clone());
    assert!(matches!(child_state, Err(Error::EventOutOfOrderError)));

    // Check if processed drt is in kel.
    let drt_from_db = event_processor.db.last_event_at_sn(&child_prefix, 1);
    assert!(matches!(drt_from_db, Ok(None)));

    event_processor.process(deserialized_ixn_drt.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_processor.db.last_event_at_sn(&bobs_pref, 2).unwrap();
    assert_eq!(ixn_from_db, Some(raw_parsed(deserialized_ixn_drt)?));

    // Process delegated rotation event once again.
    event_processor.process(deserialized_drt.clone())?.unwrap();

    // Check if processed drt event is in db.
    let drt_from_db = event_processor
        .db
        .last_event_at_sn(&child_prefix, 1)
        .unwrap();
    assert_eq!(drt_from_db, Some(raw_parsed(deserialized_drt)?));

    Ok(())
}
