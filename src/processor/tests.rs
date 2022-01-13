use super::EventProcessor;
use crate::event::sections::seal::EventSeal;
use crate::event_message::Digestible;
use crate::event_message::signed_event_message::Message;
use crate::event_parsing::message::{signed_event_stream, signed_message};
use crate::{database::sled::SledEventDatabase, error::Error};
use crate::{
    prefix::IdentifierPrefix,
};
use std::convert::TryFrom;
use std::fs;
use std::sync::Arc;

#[test]
fn test_process() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));
    // Events and sigs are from keripy `test_multisig_digprefix` test.
    // (keripy/tests/core/test_eventing.py#1138)

    let icp_raw = br#"{"v":"KERI10JSON00017e_","t":"icp","d":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"0","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAA39j08U7pcU66OPKsaPExhBuHsL5rO1Pjq5zMgt_X6jRbezevis6YBUg074ZNKAGdUwHLqvPX_kse4buuuSUpAQABphobpuQEZ6EhKLhBuwgJmIQu80ZUV1GhBL0Ht47Hsl1rJiMwE2yW7-yi8k3idw2ahlpgdd9ka9QOP9yQmMWGAQACM7yfK1b86p1H62gonh1C7MECDCFBkoH0NZRjHKAEHebvd2_LLz6cpCaqKWDhbM2Rq01f9pgyDTFNLJMxkC-fAQ"#;
	let parsed = signed_message(icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();

    let id = match &deserialized_icp {
        Message::Event(e) => e.event_message.event.get_prefix(),
        _ => Err(Error::SemanticError("bad deser".into()))?,
    };

    // Process icp event.
    event_processor.process(deserialized_icp)?.unwrap();

    // Check if processed event is in kel.
    let icp_from_db = event_processor.get_event_at_sn(&id, 0).unwrap();
    let re_serialized = icp_from_db.unwrap().signed_event_message.serialize().unwrap();
    assert_eq!(icp_raw.to_vec(), re_serialized);

    let rot_raw = br#"{"v":"KERI10JSON0001b3_","t":"rot","d":"E0UUmo4JsLq9C6LDnerxTjV0PcegpXcPsT_m2J4SeQbE","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"1","p":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","kt":"2","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ","D1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU","D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM"],"n":"EQpRYqbID2rW8X5lB6mOzDckJEIFae6NbJISXgJSN9qg","bt":"0","br":[],"ba":[],"a":[]}-AADAATWNmB15NNCgCUeFmDv9HbSkPzZ3hK1oS4DAnBVvA1hSkBm1biGDGPIVRPMLqB_MhAy516DV7B7AQs7eoS5b1DgABOXlDXb4TktNyn_Iindz3GLwRkH_lRo3rfez107T1GfoHFetzbpx3uQExyiuiQM2JRWuHCe3wUFdhzjqQ2_MpAgACVMBC6elfrKOfs2ZQxyXrzkuxNCgpgDBPmstysWo2P6GA2epCGnKwUPq83S_g6RC6oCl9N0-DEWf7tgaD0aTcCg"#;
	let parsed = signed_message(rot_raw).unwrap().1;
    let deserialized_rot = Message::try_from(parsed).unwrap();

    // Process rotation event.
    event_processor.process(deserialized_rot.clone())?.unwrap();
    let rot_from_db = event_processor.get_event_at_sn(&id, 1).unwrap().unwrap();
    assert_eq!(
        rot_from_db.signed_event_message.serialize().unwrap(),
        rot_raw
    );

    // Process the same rotation event one more time.
    let id_state = event_processor.process(deserialized_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventDuplicateError)));

    let ixn_raw = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"E2R3qlKVg96GqkpGGaIVgjEDy_3Zklm5l0JJaI2g7lqY","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"2","p":"E0UUmo4JsLq9C6LDnerxTjV0PcegpXcPsT_m2J4SeQbE","a":[]}-AADAAUHrvRANKmre1dXRNpBeJFTRBouy4Wmj72QHjBrv74JtKBq7_JzYz17A5Kem6wk5IjOi7Q3gtoxQc4a3xDXHkBwABnHvoCVgqyZZxxdVRY74SHItB8IDVK9udSY8eID7m-oktOm6mtRSbazNRq0gsCh0IwzH_-7REtFvO7CO-noQgCwACr7Re0-LgCMTtBpsq5wK7YqwSpqP6-YLu1m9IOQWv5O9zGAp-z6Qbp1x9cpMGrpTEJTHLp2PNtdTzffvztWuBBQ"#;
	let parsed = signed_message(ixn_raw).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();

    // Process interaction event.
    event_processor.process(deserialized_ixn.clone())?.unwrap();

    // Check if processed event is in db.
    let ixn_from_db = event_processor.get_event_at_sn(&id, 2).unwrap().unwrap();
    match deserialized_ixn {
        Message::Event(evt) => assert_eq!(
            ixn_from_db.signed_event_message.event_message.event,
            evt.event_message.event
        ),
        _ => assert!(false),
    }

    // Construct partially signed interaction event.
    let ixn_raw_2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"E1dzN2DTAXoC3HsdbUuiGB8nDOCYMeAtAeulBT0ljDgs","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"3","p":"E2R3qlKVg96GqkpGGaIVgjEDy_3Zklm5l0JJaI2g7lqY","a":[]}-AADAAMXFghkY_dHBEDE5tHvbPu3NNwYEE8lVyYQrxvpbuXRq50jGOekJ8JoSj-_ysjD6j5Yd6fwS_h92Ie0jP-4epCQAB3CJfe8LDC3FP7RsIt4Weu0ks8IyuqeqJ_g_uko5436TONysurOp76RKisehot0SQBUcFPZ5Yp90XFb5dq661DwACJnPkO6ypAZAEkj7Wn6w0Re0Nym2mvNpxefwANJbRZPoBdAn94nKrxJW9S8jePZ49EBihU8R5j6j7Bc2rMMD7AA"#;
	let parsed = signed_message(ixn_raw_2).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();
    // Make event partially signed.
    let partially_signed_deserialized_ixn = match deserialized_ixn {
        Message::Event(mut e) => {
            let sigs = e.signatures[1].clone();
            e.signatures = vec![sigs];
            Message::Event(e)
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
    let out_of_order_rot_raw = br#"{"v":"KERI10JSON000187_","t":"rot","d":"E5QnF__pQnqFHkHfIjZr4saPnEnzNelDRM9jEENN6WQs","i":"ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk","s":"4","p":"E1dzN2DTAXoC3HsdbUuiGB8nDOCYMeAtAeulBT0ljDgs","kt":"2","k":["D4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM","DVjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4","DT1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg"],"n":"","bt":"0","br":[],"ba":[],"a":[]}-AADAADjTnTZ5cisTrUXSgnYJpbKoNra2IRRSglzwn2b-WtF99gUixNUIl1KNilQJn0pQlRngPZUKbAxhBgqRvXqWFAgABX0mBBLQ1IMtlzDzEYXDPwztt-ySMFQszQAY7TGSrwzuSMFFA5mBBxxg_muulDClcNAYVt3iKdUodT8N0q-33CwACAyzq3lRXJonJl1X2f9IXBZZiiyIhyetWhNETXjiRbKZKJohfuhSVXsnigwWGscc0S1t_hRTbdB1ijq6fJ4UhBg"#;
	let parsed = signed_message(out_of_order_rot_raw).unwrap().1;
    let out_of_order_rot = Message::try_from(parsed).unwrap();

    let id_state = event_processor.process(out_of_order_rot);
    assert!(id_state.is_err());
    assert!(matches!(id_state, Err(Error::EventOutOfOrderError)));

    // Check if processed event is in kel. It shouldn't.
    let raw_from_db = event_processor.get_event_at_sn(&id, 4);
    assert!(matches!(raw_from_db, Ok(None)));

    let id: IdentifierPrefix = "ELYk-z-SuTIeDncLr6GhwVUKnv3n3F1bF18qkXNd2bpk".parse()?;
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
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_direct_mode` test.
    // (keripy/tests/core/test_eventing.py)
    // Parse and process controller's inception event.
    let icp_raw = br#"{"v":"KERI10JSON000120_","t":"icp","d":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","i":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAAWKO9bl3OhABTaevxYiXQ1poRIGfM9ndMPq4bvrKmU_3pTN3VLNDYOI8pJBeAQxRtajQn4CSWOqgdGnmeG6fBCQ"#;
	let parsed =  signed_message(icp_raw).unwrap().1;
    let icp = Message::try_from(parsed).unwrap();

    let controller_id_state = event_processor.process(icp)?;

    // Parse receipt of controller's inception event.
    let vrc_raw = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","i":"EsZuhYAPBDnexP3SOl9YsGvWBrYkjYcRjomUYmCcLAYY","s":"0"}-FABE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg0AAAAAAAAAAAAAAAAAAAAAAAE7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg-AABAAlIts3z2kNyis9l0Pfu54HhVN_yZHEV7NWIVoSTzl5IABelbY8xi7VRyW42ZJvBaaFTGtiqwMOywloVNpG_ZHAQ'"#;
	let parsed = signed_message(vrc_raw).unwrap().1;
    let rcp = Message::try_from(parsed).unwrap();

    let id_state = event_processor.process(rcp.clone());
    // Validator not yet in db. Event should be escrowed.
    assert!(id_state.is_err());

    // Parse and process validator's inception event.
    let val_icp_raw = br#"{"v":"KERI10JSON000120_","t":"icp","d":"E7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg","i":"E7pB5IKuaYh3aIWKxtexyYFhpSjDNTEGSQuxeJbWiylg","s":"0","kt":"1","k":["D8KY1sKmgyjAiUDdUBPNPyrSz_ad_Qf9yzhDNZlEKiMc"],"n":"EOWDAJvex5dZzDxeHBANyaIoUG3F4-ic81G6GwtnC4f4","bt":"0","b":[],"c":[],"a":[]}-AABAAsnbd4AkK3mlX2Z3quAfTznEPmFJInT9CE9i0aisswqaSW7QNp6XlPHo3natTevQCmS0H9J4Kb-H_V-BtpqavBA"#;
	let parsed = signed_message(val_icp_raw).unwrap().1;
    let val_icp = Message::try_from(parsed).unwrap();

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
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py)
    let bobs_pref: IdentifierPrefix = "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8".parse()?;

    let bobs_icp = br#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAJEloPu7b4z8v1455StEJ1b7dMIz-P0tKJ_GBBCxQA8JEg0gm8qbS4TWGiHikLoZ2GtLA58l9dzIa2x_otJhoDA"#;
	let parsed = signed_message(bobs_icp).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    event_processor.process(msg)?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON000154_","t":"dip","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"}-AABAA_zcT2-86Zll3FG-hwoQiVuFiT0X28Ft0t4fZGNFISgtZjH2DCrBGoceko604NDZ0QF0Z3bSgEkN_y0lBafD_Bw-GAB0AAAAAAAAAAAAAAAAAAAAAAQE1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc"#;
	let parsed = signed_message(dip_raw).unwrap().1;
    let deserialized_dip = Message::try_from(parsed).unwrap();

    // Process dip event before delegating ixn event.
    let state = event_processor.process(deserialized_dip.clone());
    assert!(matches!(state, Err(Error::EventOutOfOrderError)));

    let child_prefix: IdentifierPrefix = "Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI".parse()?;

    // Check if processed dip is in kel.
    let dip_from_db = event_processor.get_event_at_sn(&child_prefix, 0);
    assert!(matches!(dip_from_db, Ok(None)));

    // Bob's ixn event with delegating event seal.
    let bobs_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI"}]}-AABAA6h5mD5stIwO_rwV9apMuhHXjxrKp2ATa35u-H6DM2X-BKo5NkJ1khzBdHo-VLQ6Zw_yajj2Ul_WOL8pFSk_ZDg"#;
	let parsed = signed_message(bobs_ixn).unwrap().1;
    let deserialized_ixn = Message::try_from(parsed).unwrap();
    event_processor.process(deserialized_ixn.clone())?;

    let raw_parsed = |ev: Message| -> Result<Vec<_>, Error> {
        if let Message::Event(ev) = ev {
            ev.event_message.serialize()
        } else {
            Ok(vec![])
        }
    };

    // Check if processed event is in db.
    let ixn_from_db = event_processor.get_event_at_sn(&bobs_pref, 1).unwrap().unwrap();
    assert_eq!(ixn_from_db.signed_event_message.event_message.serialize()?, raw_parsed(deserialized_ixn)?);

    // Process delegated inception event once again.
    event_processor.process(deserialized_dip.clone())?;

    // Check if processed dip event is in db.
    let dip_from_db = event_processor
        .get_event_at_sn(&child_prefix, 0)?
        .unwrap();
        
    assert_eq!(dip_from_db.signed_event_message.event_message.serialize()?, raw_parsed(deserialized_dip.clone())?);

    // Bobs interaction event with delegated event seal.
    let bob_ixn = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"Eq-MPVuYTPXNUlQSHKfnPhiV3rWo7hkkLa7ui67OIG68","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"2","p":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"1","d":"ELEnIYF_rAsluR9TI_jh5Dizq61dCXjos22AGN0hiVjw"}]}-AABAA-QDEYYQCDtosLkziTAaWTu3mfVdFUxa8tytwQVohRwBJEhefCIaCDIbFhrrEn17KMwGoOJKBrJ7Da4WqeWbtAA"#;
	let parsed = signed_message(bob_ixn).unwrap().1;
    let deserialized_ixn_drt = Message::try_from(parsed).unwrap();

    // Delegated rotation event.
    let drt_raw = br#"{"v":"KERI10JSON000155_","t":"drt","d":"ELEnIYF_rAsluR9TI_jh5Dizq61dCXjos22AGN0hiVjw","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"1","p":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","kt":"1","k":["DTf6QZWoet154o9wvzeMuNhLQRr8JaAUeiC6wjB_4_08"],"n":"E8kyiXDfkE7idwWnAZQjHbUZMz-kd_yIMH0miptIFFPo","bt":"0","br":[],"ba":[],"a":[]}-AABAAer7S2mRuHlXxmJxy6E5lgdBmh3eeKd2TnkyivHlEw83Xhq98h6RBjXRDc_S0Z-TrLUS2u-6FnIkP_yYsOeH0Dg-GAB0AAAAAAAAAAAAAAAAAAAAAAgEq-MPVuYTPXNUlQSHKfnPhiV3rWo7hkkLa7ui67OIG68"#;
	let parsed = signed_message(drt_raw).unwrap().1;
    let deserialized_drt = Message::try_from(parsed).unwrap();

    // Process drt event before delegating ixn event.
    let child_state = event_processor.process(deserialized_drt.clone());
    assert!(matches!(child_state, Err(Error::EventOutOfOrderError)));

    // Check if processed drt is in kel.
    let drt_from_db = event_processor.get_event_at_sn(&child_prefix, 1);
    assert!(matches!(drt_from_db, Ok(None)));

    event_processor.process(deserialized_ixn_drt.clone())?;

    // Check if processed event is in db.
    let ixn_from_db = event_processor.get_event_at_sn(&bobs_pref, 2)?.unwrap();
    assert_eq!(ixn_from_db.signed_event_message.event_message.serialize()?, raw_parsed(deserialized_ixn_drt)?);

    // Process delegated rotation event once again.
    event_processor.process(deserialized_drt.clone())?.unwrap();

    // Check if processed drt event is in db.
    let drt_from_db = event_processor
        .get_event_at_sn(&child_prefix, 1)?
        .unwrap();
    assert_eq!(drt_from_db.signed_event_message.event_message.serialize()?, raw_parsed(deserialized_drt)?);

    Ok(())
}

#[test]
fn test_validate_seal() -> Result<(), Error> {
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py:#test_delegation)

    // Process icp.
    let delegator_icp_raw= br#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAJEloPu7b4z8v1455StEJ1b7dMIz-P0tKJ_GBBCxQA8JEg0gm8qbS4TWGiHikLoZ2GtLA58l9dzIa2x_otJhoDA"#;
	let parsed = signed_message(delegator_icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();
    event_processor.process(deserialized_icp.clone())?.unwrap();
    let delegator_id = "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8".parse()?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON000154_","t":"dip","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"}-AABAA_zcT2-86Zll3FG-hwoQiVuFiT0X28Ft0t4fZGNFISgtZjH2DCrBGoceko604NDZ0QF0Z3bSgEkN_y0lBafD_Bw-GAB0AAAAAAAAAAAAAAAAAAAAAAQE1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc"#;
	let parsed = signed_message(dip_raw).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    if let Message::Event(dip) = msg {
        let delegated_event_digest = dip.event_message.event.get_digest().unwrap();
        // Construct delegating seal.
        let seal = EventSeal {
            prefix: delegator_id,
            sn: 1,
            event_digest: delegated_event_digest,
        };

        // Try to validate seal before processing delegating event
        assert!(matches!(
            event_processor.validate_seal(seal.clone(), &dip.event_message),
            Err(Error::EventOutOfOrderError)
        ));
        
        // Process delegating event.
        // let delegating_event_raw = br#"{"v":"KERI10JSON000107_","i":"Eta8KLf1zrE5n-HZpgRAnDmxLASZdXEiU9u6aahqR8TI","s":"1","t":"ixn","p":"E1-QL0TCdsBTRaKoakLjFhjSlELK60Vv8WdRaG6zMnTM","a":[{"i":"E-9tsnVcfUyXVQyBPGfntoL-xexf4Cldt_EPzHis2W4U","s":"0","d":"E1x1JOub6oEQkxAxTNFu1Pma6y-lrbprNsaILHJHoPmY"}]}-AABAAROVSK0qK2gqlr_OUsnHNW_ksCyLVmRaysRne2dI5dweECGIy3_ZuFHyOofiDRt5tRE09PlS0uZdot6byFNr-AA"#;
        let delegating_event_raw = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI"}]}-AABAA6h5mD5stIwO_rwV9apMuhHXjxrKp2ATa35u-H6DM2X-BKo5NkJ1khzBdHo-VLQ6Zw_yajj2Ul_WOL8pFSk_ZDg"#;
        let parsed = signed_message(delegating_event_raw).unwrap().1;
        let deserialized_ixn = Message::try_from(parsed).unwrap();
        event_processor.process(deserialized_ixn.clone())?;
        
        // Validate seal again.
        assert!(event_processor
            .validate_seal(seal, &dip.event_message)
            .is_ok());
        };
            
    Ok(())
}

#[test]
fn test_compute_state_at_sn() -> Result<(), Error> {
    use crate::event::sections::seal::EventSeal;
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    let kerl_str = br#"{"v":"KERI10JSON000120_","t":"icp","d":"EFM_0I1yFtoKJPy8L9QCN9ZBHHR-qIBSxSwHZG6uljqc","i":"Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30","s":"0","kt":"1","k":["Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30"],"n":"ESY1L4c7pxgQBuq76wUjwLdOWVfX8XLfi4unqjzBs3A4","bt":"0","b":[],"c":[],"a":[]}-AABAAqVXfmQsyme65lXrnUdx701IClRnO14wvdP00-CnTyYHetVUQEpWCS787bSNWlPG9HnroeEzfuM7ZhzM5VRCQDw{"v":"KERI10JSON000155_","t":"rot","d":"EI_rE4U5HPnLtJ-kNRBZKyTzw9dYq0yffywEoGEZZE0E","i":"Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30","s":"1","p":"EFM_0I1yFtoKJPy8L9QCN9ZBHHR-qIBSxSwHZG6uljqc","kt":"1","k":["DhSM7Cy_qC1y7jmmIu8A3lYedssBAVpHKJDfVbUXo_Nc"],"n":"EAMjC1FxUcVlPHFBcgMOTjLmlRsRNkHtXzUTFD5VaaU4","bt":"0","br":[],"ba":[],"a":[]}-AABAA6TMhDKzjpD574-xzs0A0VwD5x_VzcYcK0y9h_ttkVYQOQlocK4QpsV2kHbAHptKQg74tZxxcKuiqDg1SO9MTAA{"v":"KERI10JSON0000cb_","t":"ixn","d":"EeAgPgw8ewxtbE0zVRB92K5bLC_nmVQBgA9Ajz7TPTg0","i":"Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30","s":"2","p":"EI_rE4U5HPnLtJ-kNRBZKyTzw9dYq0yffywEoGEZZE0E","a":[]}-AABAArJjuMeasjy7gcTSZrDaVa8shiYoH4syJPXPZQMRLyaxCBFFynsWVyWrq-ZJFoWJETyX3Hi5U7AmPfWZsZfaaCw{"v":"KERI10JSON000155_","t":"rot","d":"E7YSxhPZMwGRxIP4E1POsqS7gK9jO00cE0IOr002lVPI","i":"Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30","s":"3","p":"EeAgPgw8ewxtbE0zVRB92K5bLC_nmVQBgA9Ajz7TPTg0","kt":"1","k":["D4cFZmRliumCFW5RnHvDFYCRTvNvuGMLWO1CqTaNEZZI"],"n":"Ew9LxnzhZHC6wri0dFdC5OQ_uhpAaO-wjbMtdt5ld0HQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAWaOtr_k3Jk0GQn39Pc7WoZEcpeZk1m5yMScDq0yp5L4biNkSnyOA7AYO5G2n-HxZ3lM2IGeTLwN4XAdyVxRrBg{"v":"KERI10JSON000155_","t":"rot","d":"E6OMBom_RgVCE7paXEvdUBzg2rt6QRmEQ2q7Dq4FOG9o","i":"Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30","s":"4","p":"E7YSxhPZMwGRxIP4E1POsqS7gK9jO00cE0IOr002lVPI","kt":"1","k":["Dnljgftiq3x7IuF4mmMYfOzWoMNh98QDCdEU2bRSqUAQ"],"n":"EnlyNgrbZhysJ8mxSxoVuVv9QBAcB25RtVmm2A7yW7oY","bt":"0","br":[],"ba":[],"a":[]}-AABAApnOXmrsbhdRUHEg-x9CqeVKQdJIau0fTnQ8WT2uv1ueUwj7zMfWstZYEpRPkc9DAg5XqRKyMVOR2kq4sjAIpAQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"ECpHwQLdPSwHBGR_QAXhlyzwyB-z8vNYuVRtTWak5kQw","i":"Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30","s":"5","p":"E6OMBom_RgVCE7paXEvdUBzg2rt6QRmEQ2q7Dq4FOG9o","a":[]}-AABAAwj0JqH6ae5vCOCxiAWmA_FKzM1g7ydxQpfgQio0Yj2DhOPKBU8kdUh0zAM2n6qi32diaJHYM15nm62Re1sK7CQ"#;
    // Process kerl
    signed_event_stream(kerl_str)
        .unwrap()
        .1
        .into_iter()
        .for_each(|event| {
            event_processor.process(Message::try_from(event.clone()).unwrap()).unwrap();
        });

    let event_seal = EventSeal {
        prefix: "Ddhxr2UX8Xl55KvOd20cBYjj5QSCVqTiINgA_VJQul30".parse()?,
        sn: 2,
        event_digest: "EeAgPgw8ewxtbE0zVRB92K5bLC_nmVQBgA9Ajz7TPTg0".parse()?,
    };

    let state_at_sn = event_processor
        .compute_state_at_sn(&event_seal.prefix, event_seal.sn)?
        .unwrap();
    assert_eq!(state_at_sn.sn, event_seal.sn);
    assert_eq!(state_at_sn.prefix, event_seal.prefix);
    let ev_dig = state_at_sn.last.unwrap().get_digest();
    assert_eq!(event_seal.event_digest, ev_dig);

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_reply_escrow() -> Result<(), Error> {
    use tempfile::Builder;
    use crate::query::QueryError;
    
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    let identifier: IdentifierPrefix = "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8".parse()?;
    let kel = r#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAJEloPu7b4z8v1455StEJ1b7dMIz-P0tKJ_GBBCxQA8JEg0gm8qbS4TWGiHikLoZ2GtLA58l9dzIa2x_otJhoDA{"v":"KERI10JSON000155_","t":"rot","d":"EoU_JzojCvenHLPza5-K7z59yU7efQVrzciNdXoVDmlk","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","kt":"1","k":["Dyb48eeVVXD7JAarHFAUffKcgYGvCQ4KWX00myzNLgzU"],"n":"ElBleBp2wS0n927E6W63imv-lRzU10uLYTRKzHNn19IQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAXcEQQlT3id8LpTRDkFKVzF7n0d0w-3n__xgdf7rxTpAWUVsHthZcPtovCVr1kca1MD9QbfFAMpEtUZ02LTi3AQ{"v":"KERI10JSON000155_","t":"rot","d":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"2","p":"EoU_JzojCvenHLPza5-K7z59yU7efQVrzciNdXoVDmlk","kt":"1","k":["DyN13SKiF1FsVoVR5C4r_15JJLUBxBXBmkleD5AYWplc"],"n":"Em4tcl6gRcT2OLjbON4iz-fsw0iWQGBtwWic0dJY4Gzo","bt":"0","br":[],"ba":[],"a":[]}-AABAAZgqx0nZk4y2NyxPGypIloZikDzaZMw8EwjisexXwn-nr08jdILP6wvMOKZcxmCbAHJ4kHL_SIugdB-_tEvhBDg{"v":"KERI10JSON000155_","t":"rot","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"3","p":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"n":"E_Y2NMHE0nqrTQLe57VPcM0razmxdxRVbljRCSetdjjI","bt":"0","br":[],"ba":[],"a":[]}-AABAAkk_Z4jS76LBiKrTs8tL32DNMndq5UQJ-NoteiTyOuMZfyP8jgxJQU7AiR7zWQZxzmiF0mT1JureItwDkPli5DA"#;
    let parsed = signed_event_stream(kel.as_bytes()).unwrap().1;
    let kel_events = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let rest_of_kel = r#"{"v":"KERI10JSON000155_","t":"rot","d":"EChhtlv3ZbdRHk6UKxP2l6Uj1kPmloV4hSjvn7480Sks","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"4","p":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","kt":"1","k":["DcJ_93nB6lFRiuTCKLsP0P-LH2bxgnW7pzsp_i8KEHb4"],"n":"Ej3cpXIF_K6ZFnuoRn2sDz26O1YQzTqYhCpac4Lk7oo4","bt":"0","br":[],"ba":[],"a":[]}-AABAAEk-XVyuGkGtfC6MFUiSsk4o4eWGw-cBKhmZOV3DOy8b2tUB-4t6jY15vo26mn8tauvADPs321xkjX9rNBkhlCw{"v":"KERI10JSON000155_","t":"rot","d":"EfARz_ZQsxvwinu5iJ5ry0OQW8z-kSw0ULYi-EXidRpk","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"5","p":"EChhtlv3ZbdRHk6UKxP2l6Uj1kPmloV4hSjvn7480Sks","kt":"1","k":["Dw4Woc1Nto6vNe_oezp3Tw13-YujvCIf7zzy8Ua0VaZU"],"n":"EoKxnsSwdrZK9BSDKV0Am-inFCVwc0dQoco8ykRBNcbE","bt":"0","br":[],"ba":[],"a":[]}-AABAA-6rxkCizrb1fbMWzHAMbiyYqnPUBg_d6lN9Gzla49SZ9eHgxOjRxCE34N0FDObX9UuBGNLO7pIh59OMMtwKdDQ{"v":"KERI10JSON000155_","t":"rot","d":"EJyIhOR7NJjQuV_N6WsQ_qqZc5f09vVwqVnIbuiWxuFs","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"6","p":"EfARz_ZQsxvwinu5iJ5ry0OQW8z-kSw0ULYi-EXidRpk","kt":"1","k":["DjGxCjRAVaFiVffhQcPDf04bicivm2TL1LknCL3ujv50"],"n":"EE2EIFJ_RB8iHHWGdFVwxWUYOVryS9_0i-boEELGvg5U","bt":"0","br":[],"ba":[],"a":[]}-AABAAXVtZlgCbE7u5KwWe7Hmlv3NCCkVmccQUemIKand3AcYkoxQvS0KPn5WmlQjdLk6RyVCaK2enGqqeFMSOc01_Cg{"v":"KERI10JSON000155_","t":"rot","d":"EXWLIEK40fQjeYCri1Iy8sQxZzWnJdj1pHPkDBMaodoE","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"7","p":"EJyIhOR7NJjQuV_N6WsQ_qqZc5f09vVwqVnIbuiWxuFs","kt":"1","k":["DwTncFFLkqdfOx9ipPwjYMJ-Xqcw6uVgE38WbfAiH0zQ"],"n":"EZt3rYIvWZ3WuVankOuW34wSifHNx9tUjdaUImARVCyU","bt":"0","br":[],"ba":[],"a":[]}-AABAA8penO_Nr-KVvQyhDXK8KAWQfh1qoeDGNwCJ7fLmrYQ0Yx84Uh_vHX0kj41AYelgK0aNrHbaewBVqsASQsSBBDA{"v":"KERI10JSON000155_","t":"rot","d":"EArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"8","p":"EXWLIEK40fQjeYCri1Iy8sQxZzWnJdj1pHPkDBMaodoE","kt":"1","k":["DOedRyfIQe4Z-GNSlbgA8txIKyx4Li2tJ1S0Yhy7l2T8"],"n":"EuiVoq5iFTwRutHDNJHbIY43bBj3EKmk7_lmZJdPj-PU","bt":"0","br":[],"ba":[],"a":[]}-AABAAkZNVe95o9nSNSP6ck_khDy1tfKJUzu430vAi_p6fEMqVzJB4yqa2fdRBJmqwbq5gPOHwd0bE_JcbTrgnVFAQBQ"#;
    let parsed = signed_event_stream(rest_of_kel.as_bytes()).unwrap().1;
    let rest_of_kel = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let old_rpy = r#"{"v":"KERI10JSON000292_","t":"rpy","d":"E_v_Syz2Bhh1WCKx9GBSpU4g9FqqxtSNPI_M2KgMC1yI","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":{"v":"KERI10JSON0001d7_","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"3","p":"EYhzp9WCvSNFT2dVryQpVFiTzuWGbFNhVHNKCqAqBI8A","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"n":"E_Y2NMHE0nqrTQLe57VPcM0razmxdxRVbljRCSetdjjI","bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA","br":[],"ba":[]}}}-FABEt78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV80AAAAAAAAAAAAAAAAAAAAAAwEsL4LnyvTGBqdYC_Ute3ag4XYbu8PdCj70un885pMYpA-AABAAycUrU33S2856nVTuKNbxmGzDwkR9XYY5cXGnpyz4NZsrvt8AdOxfQfYcRCr_URFU9UrEsLFIFJEPoiUEuTbcCg"#;
    let parsed = signed_message(old_rpy.as_bytes()).unwrap().1;
    let deserialized_old_rpy = Message::try_from(parsed).unwrap();

    let new_rpy = r#"{"v":"KERI10JSON000292_","t":"rpy","d":"ECMNs09Snruv7bRpgUGgwflF3ZIpby7_m3jgjdIXJRno","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":{"v":"KERI10JSON0001d7_","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"8","p":"EXWLIEK40fQjeYCri1Iy8sQxZzWnJdj1pHPkDBMaodoE","d":"EArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA","f":"8","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DOedRyfIQe4Z-GNSlbgA8txIKyx4Li2tJ1S0Yhy7l2T8"],"n":"EuiVoq5iFTwRutHDNJHbIY43bBj3EKmk7_lmZJdPj-PU","bt":"0","b":[],"c":[],"ee":{"s":"8","d":"EArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA","br":[],"ba":[]}}}-VA0-FABEt78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV80AAAAAAAAAAAAAAAAAAAAACAEArexnxpGFZv4BnXzj59FrFTxCUEU1Aq3Co2iP7tA5aA-AABAA0o_SfwLPA1gA7pZxogj56Dx-n5xELQb0_Nghp7TTQh9-CIOfGQKGHk1FGQm-qRsLPQUEVya7SGKTH0QQjd6uCg"#;
    let parsed = signed_message(new_rpy.as_bytes()).unwrap().1;
    let deserialized_new_rpy = Message::try_from(parsed).unwrap();

    // Try to process out of order reply
    assert!(matches!(event_processor.process(deserialized_old_rpy.clone()), Err(Error::QueryError(QueryError::OutOfOrderEventError))));
    let escrow = event_processor.db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 1);

    let accepted_rpys = event_processor.db.get_accepted_replys(&identifier);
    assert!(accepted_rpys.is_none());

    // process kel events and update escrow
    // reply event should be unescrowed and save as accepted
    kel_events.for_each(|ev| {event_processor.process(ev).unwrap();});
    event_processor.process_escrow()?;

    let escrow = event_processor.db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

    let accepted_rpys = event_processor.db.get_accepted_replys(&identifier);
    assert_eq!(accepted_rpys.unwrap().collect::<Vec<_>>().len(), 1);

    // Try to process new out of order reply
    // reply event should be escrowed, accepted reply shouldn't change
    assert!(matches!(event_processor.process(deserialized_new_rpy.clone()), Err(Error::QueryError(QueryError::OutOfOrderEventError))));
    let mut escrow = event_processor.db.get_escrowed_replys(&identifier).unwrap();
    assert_eq!(Message::KeyStateNotice(escrow.next().unwrap()), deserialized_new_rpy);
    assert!(escrow.next().is_none());

    let mut accepted_rpys = event_processor.db.get_accepted_replys(&identifier).unwrap();
    assert_eq!(Message::KeyStateNotice(accepted_rpys.next().unwrap()), deserialized_old_rpy);
    assert!(accepted_rpys.next().is_none());

    // process rest of kel and update escrow
    // reply event should be unescrowed and save as accepted
    rest_of_kel.for_each(|ev| {event_processor.process(ev).unwrap();});
    event_processor.process_escrow()?;

    let escrow = event_processor.db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

    let mut accepted_rpys = event_processor.db.get_accepted_replys(&identifier).unwrap();
    assert_eq!(Message::KeyStateNotice(accepted_rpys.next().unwrap()), deserialized_new_rpy);
    assert!(accepted_rpys.next().is_none());

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_query() -> Result<(), Error> {
    use tempfile::Builder;
    use crate::{query::ReplyType, keri::witness::Witness};

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let witness = Witness::new(root.path())?;

    let icp_str = r#"{"v":"KERI10JSON0001ac_","t":"icp","d":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","s":"0","kt":"1","k":["DxH8nLaGIMllBp0mvGdN6JtbNuGRPyHb5i80bTojnP9A"],"n":"EmJ-3Y0pM0ogX8401rEziJhpql567YEdHDlylwfnxNIM","bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-AABAAGwlsKbtQjGUoKlYsBRksx5KmAiXWtNakJkxmxizV0aoN4d_GwtmnbNwpuuggc3CmoftruHIo_Q9CbWw-lUitDA"#;
    let parsed = signed_message(icp_str.as_bytes()).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();
    witness.processor.process(deserialized_icp)?;

    let qry_str = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EEFpGGlsAGe51BgyebzDUAs4ewWYz1HO9rytYVaxDo3c","dt":"2022-01-13T15:53:32.020709+00:00","r":"ksn","rr":"","q":{"i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk"}}-VAj-HABESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk-AABAAMOLeXG1ClCtSPP4hhtvyoWMLOvMvaiveHCepL3zh1OQcAyn2GzEh2TwjKFyKFGBXD6-blmvg8M8hDMr-yjv6Bw"#;
    let parsed = signed_message(qry_str.as_bytes()).unwrap().1;
    let deserialized_qy = Message::try_from(parsed).unwrap();

    if let Message::Query(qry) = deserialized_qy {
        let res = witness.process_signed_query(qry)?;
        assert!(matches!(res, ReplyType::Rep(_)));

    } else {
        assert!(false)
    }

    Ok(())
}