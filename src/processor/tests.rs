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
    // (keripy/tests/core/test_eventing.py#1098)

    let icp_raw = r#"{"v":"KERI10JSON000144_","i":"EIP6JVp53VZau8wPba8mMsc8wRH1eySlFvCOuMmxm_-w","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","wt":"0","w":[],"c":[]}-AADAAPGMuShtKCzc_oXMViVhVPMkAfmSyeRtQ2EHtvgRy2NrcXbx-o-vAOwMVv2gOit2JetBrIpJ9Vrk7AIqlUUfCAQABq8xN8U7XetGS5ayeX7dd9jZ4dTdNSBcF4Ov57k0TzdBh5ukwi3ocpY77qZ4vr0nlK83iIbLBu999UZ7XoljBBgACKJuVmv5usbWsDOjq_I8028pXe0Nib2YlKgKKtx1AblOCtWBU2zD_qgXUs58ACmOcFIdTfkxhR3u_jCN8XfHSAw"#;
    let deserialized_icp = parse::signed_message(icp_raw.as_bytes()).unwrap().1;

    let (id, raw_parsed) = match &deserialized_icp {
        Deserialized::Event(e) => (e.event.event.event.prefix.clone(), e.event.raw.to_vec()),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(deserialized_icp)?.unwrap();

    // Check if processed event is in kel.
    let icp_from_db = event_processor.db.last_event_at_sn(&id, 0).unwrap();
    assert_eq!(icp_from_db, Some(raw_parsed));

    let rot_raw = r#"{"v":"KERI10JSON000180_","i":"EIP6JVp53VZau8wPba8mMsc8wRH1eySlFvCOuMmxm_-w","s":"1","t":"rot","p":"EpD0mQV1R-FV-CD3nSjIyOPvUItXIu2FuUBHeq4FWsxo","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"n":"EQpRYqbID2rW8X5lB6mOzDckJEIFae6NbJISXgJSN9qg","wt":"0","wr":[],"wa":[],"a":[]}-AADAAna082cl4258N_HDljuoHW7JsjsCXQW_7oyG4L20_fDyfgPjjsnrDLQITfuAamBwG0Rf5PHB06nLBA0dm8RviBQABnL_386sC_MaKTMa8lfnkTl0Q69I45ES7ZGuQhmU6HuyNFznJ5qFlO63h7uDmxueuQdw5VycjY1_OI7PTeDqpCAACzuK1_P_u1-Z14WWPBDP64R_ZEjRHnJqHl35Ljh22jOBwdD7t6Vo-GKkEQTKVLTHf7FBsUni7l-qc4DSMdmibAA"#;
    let deserialized_rot = parse::signed_message(rot_raw.as_bytes()).unwrap().1;

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

    let ixn_raw = r#"{"v":"KERI10JSON000098_","i":"EIP6JVp53VZau8wPba8mMsc8wRH1eySlFvCOuMmxm_-w","s":"2","t":"ixn","p":"E2kVOUclXo6wqjXjCKt41rus_Ho96mYE56OlpQb0tq5s","a":[]}-AADAAoTpCeTyXrK1xjxJ_w9qIjD7lefA9-Az60f5WLGcPO2iUcIiNPgIrpvJzqxg9KYlqLccuY3jcHM-eUkATMz2AAgABTVN0lACMDRWG2wT_FjcYiVAhi7a2xVqUgUOPkmXgUGZo4tzLAYr9UB4aB8f87UQSHEF3eLkfMnDReY37Yg9fDgACOCt5-HG-_9-M5zVaMIAmRw5B38mbsQ2cTmduOLtWF6wu9PSoXMiDmJs1O47apUtXgTOWESQjMkLX32kLIv5hBw"#;
    let deserialized_ixn = parse::signed_message(ixn_raw.as_bytes()).unwrap().1;

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
    let ixn_raw = r#"{"v":"KERI10JSON000098_","i":"EIP6JVp53VZau8wPba8mMsc8wRH1eySlFvCOuMmxm_-w","s":"3","t":"ixn","p":"E7BKx8z9PBrqMbFBeGiOCtmztcis5wYr00A_JKR-LNTk","a":[]}-AADAA_PKQF2k_24rdwuegqnBbYZNupL_PK0cohtva28ljBAJL0bsL6E_jrkKKQhf94zS83xo7q_RtXz0vdPzf331zBAABgOrBBLxB5_B4xacS8sQl56W_ovRfY9JKYznc7-tUtx7tuAlJbLIqvX31BOj11n1tBWBGtSJl6jozNMbl7YfEAQACPRBxWdlhJq_sko6s9HmzCO_979nAeGF1uMKrvuS7F267dsZ6uDRSbXdxTPy8sTSQILFug5v-iumvZFo-X8usDw"#;
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
    let out_of_order_ixn_raw = r#"{"v":"KERI10JSON000098_","i":"EIP6JVp53VZau8wPba8mMsc8wRH1eySlFvCOuMmxm_-w","s":"4","t":"ixn","p":"E7BKx8z9PBrqMbFBeGiOCtmztcis5wYr00A_JKR-LNTk","a":[]}-AADAA_PKQF2k_24rdwuegqnBbYZNupL_PK0cohtva28ljBAJL0bsL6E_jrkKKQhf94zS83xo7q_RtXz0vdPzf331zBAABgOrBBLxB5_B4xacS8sQl56W_ovRfY9JKYznc7-tUtx7tuAlJbLIqvX31BOj11n1tBWBGtSJl6jozNMbl7YfEAQACPRBxWdlhJq_sko6s9HmzCO_979nAeGF1uMKrvuS7F267dsZ6uDRSbXdxTPy8sTSQILFug5v-iumvZFo-X8usDw"#;
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
    // (keripy/tests/core/test_eventing.py#1791)
    // Parse and process controller's inception event.
    let icp_raw = r#"{"v":"KERI10JSON0000e6_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"icp","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","wt":"0","w":[],"c":[]}-AABAAMiMnE1gmjqoEuDmhbU7aqYBUqKCqAmrHPQB-tPUKSbH_IUXsbglEQ6TGlQT1k7G4VlnKoczYBUd7CPJuo5TnDg"#;
    let icp = parse::signed_message(icp_raw.as_bytes()).unwrap().1;

    let controller_id_state = event_processor.process(icp)?;

    // Parse receipt of controller's inception event.
    let vrc_raw = r#"{"v":"KERI10JSON000105_","i":"ENqFtH6_cfDg8riLZ-GDvDaCKVn6clOJa7ZXXVXSWpRY","s":"0","t":"vrc","d":"E9ZTKOhr-lqB7jbBMBpUIdMpfWvEswoMoc5UrwCRcTSc","a":{"i":"EmGTyV9unQ59uIQIYv6Vsc7KweyTbplfumEV-IB33bEg","s":"0","d":"E-_qFJZK8ER6rJA7W4WR2xxSwKT1RLi8yCCyZ0XHTnLU"}}-AABAAmptM4R0KnuzFtY4WTqdzUOuhkD_Rl6dKyX8a71NdoZSbCE5hbBlGh4NoxkdchGuF0jM1Ss-uHUfdoyICZsQvCg"#;
    let rcp = parse::signed_message(vrc_raw.as_bytes()).unwrap().1;

    let id_state = event_processor.process(rcp.clone());
    // Validator not yet in db. Event should be escrowed.
    assert!(id_state.is_err());

    // Parse and process validator's inception event.
    let val_icp_raw = r#"{"v":"KERI10JSON0000e6_","i":"EmGTyV9unQ59uIQIYv6Vsc7KweyTbplfumEV-IB33bEg","s":"0","t":"icp","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","wt":"0","w":[],"c":[]}-AABAApBSsY9FoB9RRRL3L4YTri4cY2RWtk2I3oX6z7fZLc4Nh7AB_d9yZya5cVWhuFiLFSrDYNpFvHBYWAix4CfhTAQ"#;
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

    let bobs_pref: IdentifierPrefix = "DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M".parse()?;

    let bobs_icp = r#"{"v":"KERI10JSON0000e6_","i":"DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M","s":"0","t":"icp","kt":"1","k":["DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M"],"n":"ESyIFWDsYD1eCki8Xh8m3VTNvd_GcLa6weSjMkr1vGDM","wt":"0","w":[],"c":[]}-AABAAGMO_be5iMRqzULrWB9TP2BRuoxEMn4sxAxzrmcdMgYoRTHBxJpVeJ0R9NQQ_q_Kk_6CEpwt0fzHe4KFy1h1bBA"#;
    let msg = signed_message(bobs_icp.as_bytes()).unwrap().1;
    event_processor.process(msg)?;

    // Delegated inception event.
    let dip_raw = r#"{"v":"KERI10JSON000165_","i":"Eillkf6Neo-Zmyn6Gg_8FS84RKWYgXblfoSXaOpttP7U","s":"0","t":"dip","kt":"1","k":["DSYuIQQrIi0N_a5gdzeXoqsNvo7PWHkn5ZrYO_ZmZdOA"],"n":"ESmikz_J7quPeKcfD_7d7jPDOfBsomZcg5I35vjMb69o","wt":"0","w":[],"c":[],"da":{"i":"DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M","s":"1","t":"ixn","p":"EnpsziyP_HrXY0GTDKn6jBCTq37akJ5W4nu3zGE9Nh5I"}}-AABAAtxbG6zfWOp73s5zxsKxXkrOi7h0CAbdYy5vBNmrG_oivi1uREgH7dUR-bpDO1lnMkcwg2ooDIIou_Ejs4bYpBA"#;
    let deserialized_dip = signed_message(dip_raw.as_bytes()).unwrap().1;

    // Process dip event before delegating ixn event.
    let state = event_processor.process(deserialized_dip.clone());
    assert!(matches!(state, Err(Error::EventOutOfOrderError)));

    let child_prefix: IdentifierPrefix = "Eillkf6Neo-Zmyn6Gg_8FS84RKWYgXblfoSXaOpttP7U".parse()?;

    // Check if processed dip is in kel.
    let dip_from_db = event_processor.db.last_event_at_sn(&child_prefix, 0);
    assert!(matches!(dip_from_db, Ok(None)));

    // Bob's ixn event with delegating event seal.
    let bobs_ixn = r#"{"v":"KERI10JSON0000ff_","i":"DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M","s":"1","t":"ixn","p":"EnpsziyP_HrXY0GTDKn6jBCTq37akJ5W4nu3zGE9Nh5I","a":[{"i":"Eillkf6Neo-Zmyn6Gg_8FS84RKWYgXblfoSXaOpttP7U","d":"E-wVeNYeC-ft2R-eq1khZzBpJV4owTKLEMn5Qgb7ClzE"}]}-AABAAgaeWumWSWP9tfUpZYGP0W3DU2Wd20NheRMjSS7QcW8AeKMfgklLfqOLE_B5cF6G_GhcMtthDyK4oEffZ_Tm8Bg"#;
    let deserialized_ixn = signed_message(bobs_ixn.as_bytes()).unwrap().1;
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
    let bob_ixn = r#"{"v":"KERI10JSON0000ff_","i":"DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M","s":"2","t":"ixn","p":"EDtl3GufXTAMhokeiHr0CM-N1X2clxGXhB9b9ci10Uug","a":[{"i":"Eillkf6Neo-Zmyn6Gg_8FS84RKWYgXblfoSXaOpttP7U","d":"E2hTgse4VcbsV_gJUEcTRx5DiZR-lgPrpYhtSGBBFt0E"}]}-AABAADpc3e49teDDinBTETcGpQWtP0QChXEmO_5x5T8KYcTu-hRBl-TvKIY0TK04D6kRBlQnteRu-RcX1uGNiQ1j6Dw"#;
    let deserialized_ixn_drt = signed_message(bob_ixn.as_bytes()).unwrap().1;

    // Delegated rotation event.
    let drt_raw = r#"{"v":"KERI10JSON0001a1_","i":"Eillkf6Neo-Zmyn6Gg_8FS84RKWYgXblfoSXaOpttP7U","s":"1","t":"drt","p":"E-wVeNYeC-ft2R-eq1khZzBpJV4owTKLEMn5Qgb7ClzE","kt":"1","k":["DWd0PYkfyJ3zZqh7nSi5ofwynBpGZocUpG6PA2bn21B0"],"n":"ETeDZvAk4Yj5n_rjSxRN7KYchOFTqqN-HcvMf86hU9gM","wt":"0","wr":[],"wa":[],"a":[],"da":{"i":"DacyrOTuGEE1O5T0-JfoZxm_9tYRqKn5iKKzcXGe629M","s":"2","t":"ixn","p":"EDtl3GufXTAMhokeiHr0CM-N1X2clxGXhB9b9ci10Uug"}}-AABAA4hOqk3e9YQd_caNU7fuVK2N5xpYeGv6hykwYfO51AaSoyNPpKjfx2nO_Y2Mt6i4llYUBkKLwaV1b4m7CrlCcAQ"#;
    let deserialized_drt = signed_message(drt_raw.as_bytes()).unwrap().1;

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
