use alexandria_merkle_tree::storage_proof::{
    ContractStateProof, ContractData, TrieNode, BinaryNode, EdgeNode, BinaryNodeImpl, EdgeNodeImpl, verify, verify_mpt_proof, Membership
};

use alexandria_merkle_tree::tests::storage_proof_test_data::{balance_proof, total_balance_proof};

const DAI: felt252 = 0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3;
const ETH: felt252 = 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7;

#[test]
#[available_gas(2000000)]
fn balance_lsb_proof_test() {
    let state_commitment = 0x07dc88984a2d8f9c2a6d2d431b2d8f2c32957da514c16ceef0761b6933121708;
    let contract_address = DAI;
    let storage_address = 0x4ae51d08cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ee;
    let expected_value = 8700000000000000005;
    let proof = balance_proof();
    let value = verify(state_commitment, contract_address, storage_address, proof);
    assert_eq!(expected_value, value, "wrong value");
}

#[test]
#[should_panic(expected: ('invalid proof path',))]
#[available_gas(2000000)]
fn balance_msb_proof_test() {
    let state_commitment = 0x07dc88984a2d8f9c2a6d2d431b2d8f2c32957da514c16ceef0761b6933121708;
    let contract_address = DAI;
    let storage_address = 0x4ae51d08cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ef;
    let expected_value = 8700000000000000005;
    let proof = balance_proof();
    let value = verify(state_commitment, contract_address, storage_address, proof);
    assert_eq!(expected_value, value, "wrong value");
}

#[test]
#[should_panic(expected: ('invalid node hash',))]
#[available_gas(2000000)]
fn wrong_contract_address_proof_test() {
    let state_commitment = 0x07dc88984a2d8f9c2a6d2d431b2d8f2c32957da514c16ceef0761b6933121708;
    let contract_address = ETH;
    let storage_address = 0x4ae51d08cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ee;
    let expected_value = 8700000000000000005;
    let proof = balance_proof();
    let value = verify(state_commitment, contract_address, storage_address, proof);
    assert_eq!(expected_value, value, "wrong value");
}

#[test]
#[available_gas(50000000)]
fn total_balance_lsb_proof_test() {
    let state_commitment = 0x07dc88984a2d8f9c2a6d2d431b2d8f2c32957da514c16ceef0761b6933121708;
    let contract_address = DAI;
    let storage_address = 0x37a9774624a0e3e0d8e6b72bd35514f62b3e8e70fbaff4ed27181de4ffd4604;
    let expected_value = 2970506847688829412026631;
    let proof = total_balance_proof();
    let value = verify(state_commitment, contract_address, storage_address, proof);
    assert_eq!(expected_value, value, "wrong value");
}

#[test]
#[available_gas(50000000)]
fn verify_mpt_proof_correctly() {
    // Test Inclusion 
    let root = 0x04946c7636b878064ddaab68a34c440f7961b854934e9b7347d981f9f5f768f2;
    let key = 0x068ba2a188dd231112c1cb5aaa5d18be6d84f6c8683e5c3a6638dee83e727acc;
    let proof = array![
        TrieNode::Binary(BinaryNodeImpl::new(0x01f387675be9603ca64faee950fc41c70c4e8c534fb9ac6d235bf7ef732fdbb6,0x01bdac12073dd4161c28740f654bdd4162aad1e8c0588989f7d05977fc5ef41e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00f618893b917332d0f527205f94ab7bd8ab20da5b60be66f22b90d08100aba4,0x0001e996b4969876b0d24e9c9446f9aa9efef959462e2a9e800945942d4d0b63)),
        TrieNode::Binary(BinaryNodeImpl::new(0x07cf400d095212c51ce3320971de539643d8eabaffb4c2a4369e222f3606f03a,0x0321dba462885b2a1969701b2c9efebb1407a0c1108fe27da6f54db7808721d2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x02051cd969f864999bb8849bc81b7f9269da475cfe3917572ee45019c1848bbf,0x06a08b555530572d8ef951bcc258775dd8f9a16491b5ef9ce1d6487469b09cd3)),
        TrieNode::Binary(BinaryNodeImpl::new(0x0484d955456ffe836bc76ca68ed0346f8000d49b1d4390752bdcf463fb9ff8df,0x075bbd3fefcbc80a4bfa9f7966fa922ef1e8b06296c74fdb027fccf86e1f8653)),
        TrieNode::Binary(BinaryNodeImpl::new(0x03356b189a13b373a5b314df50ea23890ae30238f2874f5c0f6c43d48c478a9b,0x052bc30d623a2e5250bba867a6caad82fa0b4c7fae8bb1c14322d5a254dd6a95)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01098d6468cf066f501660a61a8d75190a3210fedc18c847be02c195d6722188,0x04d779eab03f4c8ee3c6e1bbdf7ca0cd17118dbde0d466d802d7712f0b65e4ba)),
        TrieNode::Binary(BinaryNodeImpl::new(0x0564dc25df5ea2d3c2ce68eec7295b65377b7ce36d5ade782f863391f6a442b3,0x077693e2d55eca151f494e6dec1cf291b0c62cc03b0f5c9d84b044737345fd04)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01c96fd8ff1ef78091004a87badb3640cfb7ce0254f01bcad717ab0d81f9649f,0x0346c845e8efd9360317e8b4b80e2969082ae4a6c3425fe84791df12b4c68fa6)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00a3857a5d171d57bcaac627c2b79eda657ae37ad97837c8e056c2edeb802495,0x00fd425d1e7f42d5c25501a3ce65c57520e1c45b459794b99c304a33315065eb)),
        TrieNode::Edge(EdgeNodeImpl::new(0x01a2a188dd231112c1cb5aaa5d18be6d84f6c8683e5c3a6638dee83e727acc, 0x02c25f304f5a12b4497a481a363a32a40d5891e4360dbd9de61f0117703f1f36, 241))
    ];

    let res = verify_mpt_proof(root, key, proof);
    assert(res == Option::Some(Membership::Included(1248050996070649414396845444796915005109664324995260892124683528808398004022)), 'it works!');

    // Test Inclusion Multiple Edge Nodes
    let root = 0x04946c7636b878064ddaab68a34c440f7961b854934e9b7347d981f9f5f768f2;
    let key = 0x0759f32296ec292b2b4fdf4ce2ab51314bedb9be3456b18689279274c62004c1;
    let proof = array![
        TrieNode::Binary(BinaryNodeImpl::new(0x01f387675be9603ca64faee950fc41c70c4e8c534fb9ac6d235bf7ef732fdbb6,0x01bdac12073dd4161c28740f654bdd4162aad1e8c0588989f7d05977fc5ef41e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00f618893b917332d0f527205f94ab7bd8ab20da5b60be66f22b90d08100aba4,0x0001e996b4969876b0d24e9c9446f9aa9efef959462e2a9e800945942d4d0b63)),
        TrieNode::Binary(BinaryNodeImpl::new(0x07cf400d095212c51ce3320971de539643d8eabaffb4c2a4369e222f3606f03a,0x0321dba462885b2a1969701b2c9efebb1407a0c1108fe27da6f54db7808721d2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x04a2a67938a30148e2122d6fcf1f4d2a8a3d0aae210561172ddd464883ce7b21,0x0260a7f8ec1bcc0daaf25fd848a99971aa7671a80bc70f7807383948d42c92a6)),
        TrieNode::Binary(BinaryNodeImpl::new(0x028cc7e12e96accc03f46be90dfdfd71a8784554ad141bebf945d94eff9491ec,0x073b2437cd6a589e8d71239256386f2058b1f47335ec3fbf7e0f494d3a76ef00)),
        TrieNode::Binary(BinaryNodeImpl::new(0x03687a62fa62b5f7591834e9f7f9a9719d9509c1d17ed62d0f2a59c36903c84a,0x030423db6cab22bac5b3a76669268df1400a33ad09a6fed3231b726592c5ff64)),
        TrieNode::Binary(BinaryNodeImpl::new(0x0657f678f1ab4cdbd1ee8c8155bfdb8829072c8d7a6075623942f16dcaab9356,0x069568988fe00ebacebe7e5a04841e7e7d16fd96d9d4691fc40826f205ad216e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x05f10727387bfbda71818a4c020c3621c39e133f2281aef38107375d3ee552a4,0x04f57665e066d0977f1866f648a39f74dfc8f6cb523a74044a04676e29a9ae5e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x05a306e9abc76fb78fcfb687badf05505c233ee7c4f29a130273fe4e6e7c6076,0x0575d889875d899cd31bdc5b6485c39f79df834fbfb2180f2761071cb6844ccd)),
        TrieNode::Binary(BinaryNodeImpl::new(0x006fbb6151a9792d92068ab775d981caf944e1426d042965bcdc46a22b4b7f02,0x03506e89928b685d30b4e7fd04ccdf2e1d7fa598226f8340feb39814f52c3671)),
        TrieNode::Edge(EdgeNodeImpl::new(0x0000000000000000000000000000000000000000000000000000000000000003, 0x05e8a8c69651f5f47e0384d0f71dba57a660c02a57d4a318b6161031d2fb6639, 2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x03937a6283972d485392da517301b2c3af89685ca0b96433050814172e097f76,0x0420b6820c32deb7e26098f351319c08697dc0180cda346779e502834d760ea4)),
        TrieNode::Edge(EdgeNodeImpl::new(0x0000332296ec292b2b4fdf4ce2ab51314bedb9be3456b18689279274c62004c1, 0x07e704b4c5faed6238a37b62b80a45d3488916aa0fa842a813f5a04b4661cbb8, 238))
    ];

    let res = verify_mpt_proof(root, key, proof);
    assert(res == Option::Some(Membership::Included(3574364092672205702516898695783452043330964574546146246602102132808683211704)), 'it works!');

    // No Inclusion
    let root = 0x04946c7636b878064ddaab68a34c440f7961b854934e9b7347d981f9f5f768f2;
    let key = 0x07f772b4a9855e925d6e25370386cae7feb0738bfaa760b55f354ff68a016bbb;
    let proof = array![
        TrieNode::Binary(BinaryNodeImpl::new(0x01f387675be9603ca64faee950fc41c70c4e8c534fb9ac6d235bf7ef732fdbb6,0x01bdac12073dd4161c28740f654bdd4162aad1e8c0588989f7d05977fc5ef41e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00f618893b917332d0f527205f94ab7bd8ab20da5b60be66f22b90d08100aba4,0x0001e996b4969876b0d24e9c9446f9aa9efef959462e2a9e800945942d4d0b63)),
        TrieNode::Binary(BinaryNodeImpl::new(0x07cf400d095212c51ce3320971de539643d8eabaffb4c2a4369e222f3606f03a,0x0321dba462885b2a1969701b2c9efebb1407a0c1108fe27da6f54db7808721d2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x04a2a67938a30148e2122d6fcf1f4d2a8a3d0aae210561172ddd464883ce7b21,0x0260a7f8ec1bcc0daaf25fd848a99971aa7671a80bc70f7807383948d42c92a6)),
        TrieNode::Binary(BinaryNodeImpl::new(0x03491251a53e9c5bec49cc660d56ca385e73083d6718e29fb97e4807c9e30313,0x06ceaa10a3aaa88c2e8854580d6b07e830962b09347ce347b46cc72dfa6489d1)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00f8bf8528760fe6b0222695ede29ffae141c56cdb213d4e1466e14ce4e8276d,0x00929c3f7cef440f97eede9e24d14b5e0a63a66cae78a5382012fd7bfe9f3504)),
        TrieNode::Binary(BinaryNodeImpl::new(0x062d74b8320ace1044838eb51482fda8665312c073bb7bcbaa9dfe269ea02e66,0x05ff3df449b7b21b776cace2b50fa55661c6392123c648570999845352eb9fd4)),
        TrieNode::Binary(BinaryNodeImpl::new(0x006272dff0610fc4002f1c938bd7881bb64d3f6faec0a6bf5c70ca7e3621f07c,0x01076040d2fcf662ef1ea965be7861879c7bba9ef042cb7c3805071d23d02524)),
        TrieNode::Binary(BinaryNodeImpl::new(0x03f9b70ed8775c6a82de52454a0afb07d411c723b5a2b8c8112a8cb0231df612,0x0105b7061c0ff9ec6b3b4a214f25860efe841215ce3ae8a48b9ecdbe78afb2de)),
        TrieNode::Binary(BinaryNodeImpl::new(0x0700308f65ad92429798078e94796ed3d527ab5b5abb23f8fe7d01668a1be5f1,0x0703d8c398ce5658cb691fda4f4128c8f2d0dfcc54e3c52527056d367fb8b17c)),
        TrieNode::Edge(EdgeNodeImpl::new(0x0000000000000000000000000000000000000000000000000000000000000000, 0x06c757f42b0fedf1235795910d9fc31a473a229a5001f536240ff7e9e7af6669, 3))
    ];

    let res = verify_mpt_proof(root, key, proof);
    assert(res == Option::Some(Membership::NotIncluded), 'it works!');

    // Invalid Proof
    let root = 0x04946c7636b878064ddaab68a34c440f7961b854934e9b7347d981f9f5f768f2;
    let key = 0x04bd06380495cdd0b2ad24159d4dadf3b814a4dcb3c7f1c0320e7ab557701a08;
    let proof = array![
        TrieNode::Binary(BinaryNodeImpl::new(0x01f387675be9603ca64faee950fc41c70c4e8c534fb9ac6d235bf7ef732fdbb6,0x01bdac12073dd4161c28740f654bdd4162aad1e8c0588989f7d05977fc5ef41e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00f618893b917332d0f527205f94ab7bd8ab20da5b60be66f22b90d08100aba4,0x0001e996b4969876b0d24e9c9446f9aa9efef959462e2a9e800945942d4d0b63)),
        TrieNode::Binary(BinaryNodeImpl::new(0x024e0353771899f4914cfae5584fbab7818193956d3d4e13fa161213b8718ae5,0x05329ab53b7a3b59928c6cc431a907a9298e763af1305fb0e6c06a1b1bca5aa5)),
        TrieNode::Binary(BinaryNodeImpl::new(0x04d32327e2a5c33de295638d7431a01ad683806ec5d5c4baa1e49f6fb124b67e,0x013fdd24d9e6098fdf0a764125c55ffc9cc157da1a5dbfc7363f9d16392cfc79)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01ac26f9d089d784d8fc0314c4a3af515d0926f6060de406ed13be62a6a57658,0x027315f79eba55ebdb20733066944c3f85a87df49abbafb617eda4dbbdfe0a2b)),
        TrieNode::Binary(BinaryNodeImpl::new(0x013346bf653869e6dfb9c50c629067c8ebbf12455cfa1ed1c4a801bce268d284,0x0119ec6adb71dfaffbcadae6cc1a0155d730624b94d79ade925fda284cebfed2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01cfdeaa5ff1dfe8f44df46cfbc7e188cc6b7911eb422ba9fc143734e76d4bc3,0x07f2a1f0e546b809358a83369136a66f0f5940e4f179b835298e77f948a7f2d2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x0775482a0487931679742d488960e72876b5c4a962aca71db2bf71ae3129392a,0x02e8754f617d378d094b3d9f52d7620a13ec80294068d4060deb5393dd9c8583)),
        TrieNode::Binary(BinaryNodeImpl::new(0x02940f0ba8b001aafece7edac2e6c1e7d9f5f26ef05e1b2d73401c409d90b03b,0x057568b881608861226a10f327ae42970354afbb2280902befe0c952f93a9098)),
        TrieNode::Edge(EdgeNodeImpl::new(0x00, 0x023f85f2501db36234e6c5a8ce5b75c8c97a4871a1f6b71e7c5687826f59ce6a, 1)),
        TrieNode::Binary(BinaryNodeImpl::new(0x07252c9f96510e5728a7fadb3a280c1d60289f4c971afbad67c5859d745170c0,0x034a56bd7abceb632b85e6bd4b26acccc9c8125dfb93fcbdbc221881cfac75cf)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01ddca4a2b72a4c62b2781bf9a33888d7a3b3e298c147797440e2fa69e6cbf33,0x025af085398a5e229bf586fd900bcd192d1d0d987217baafc74f95b698fe6151)),
        TrieNode::Edge(EdgeNodeImpl::new(0x06380495cdd0b1ad24159d4dadf3b814a4dcb3c7f1c0320e7ab557701a08, 0x04f1a9ead7881ae6068230eb986ed7deeaa78f3d0547630e8bfb4650fd96e46f, 239))
    ];

    let res = verify_mpt_proof(root, key, proof);
    assert(res == Option::None, 'it works!');

    // Invalid key
    let root = 0x04946c7636b878064ddaab68a34c440f7961b854934e9b7347d981f9f5f768f2;
    let key = 0x03bd06380495cdd0b2ad24159d4dadf3b814a4dcb3c7f1c0320e7ab557701a08;
    let proof = array![
        TrieNode::Binary(BinaryNodeImpl::new(0x01f387675be9603ca64faee950fc41c70c4e8c534fb9ac6d235bf7ef732fdbb6,0x01bdac12073dd4161c28740f654bdd4162aad1e8c0588989f7d05977fc5ef41e)),
        TrieNode::Binary(BinaryNodeImpl::new(0x00f618893b917332d0f527205f94ab7bd8ab20da5b60be66f22b90d08100aba4,0x0001e996b4969876b0d24e9c9446f9aa9efef959462e2a9e800945942d4d0b63)),
        TrieNode::Binary(BinaryNodeImpl::new(0x024e0353771899f4914cfae5584fbab7818193956d3d4e13fa161213b8718ae5,0x05329ab53b7a3b59928c6cc431a907a9298e763af1305fb0e6c06a1b1bca5aa5)),
        TrieNode::Binary(BinaryNodeImpl::new(0x04d32327e2a5c33de295638d7431a01ad683806ec5d5c4baa1e49f6fb124b67e,0x013fdd24d9e6098fdf0a764125c55ffc9cc157da1a5dbfc7363f9d16392cfc79)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01ac26f9d089d784d8fc0314c4a3af515d0926f6060de406ed13be62a6a57658,0x027315f79eba55ebdb20733066944c3f85a87df49abbafb617eda4dbbdfe0a2b)),
        TrieNode::Binary(BinaryNodeImpl::new(0x013346bf653869e6dfb9c50c629067c8ebbf12455cfa1ed1c4a801bce268d284,0x0119ec6adb71dfaffbcadae6cc1a0155d730624b94d79ade925fda284cebfed2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01cfdeaa5ff1dfe8f44df46cfbc7e188cc6b7911eb422ba9fc143734e76d4bc3,0x07f2a1f0e546b809358a83369136a66f0f5940e4f179b835298e77f948a7f2d2)),
        TrieNode::Binary(BinaryNodeImpl::new(0x0775482a0487931679742d488960e72876b5c4a962aca71db2bf71ae3129392a,0x02e8754f617d378d094b3d9f52d7620a13ec80294068d4060deb5393dd9c8583)),
        TrieNode::Binary(BinaryNodeImpl::new(0x02940f0ba8b001aafece7edac2e6c1e7d9f5f26ef05e1b2d73401c409d90b03b,0x057568b881608861226a10f327ae42970354afbb2280902befe0c952f93a9098)),
        TrieNode::Edge(EdgeNodeImpl::new(0x00, 0x023f85f2501db36234e6c5a8ce5b75c8c97a4871a1f6b71e7c5687826f59ce6a, 1)),
        TrieNode::Binary(BinaryNodeImpl::new(0x07252c9f96510e5728a7fadb3a280c1d60289f4c971afbad67c5859d745170c0,0x034a56bd7abceb632b85e6bd4b26acccc9c8125dfb93fcbdbc221881cfac75cf)),
        TrieNode::Binary(BinaryNodeImpl::new(0x01ddca4a2b72a4c62b2781bf9a33888d7a3b3e298c147797440e2fa69e6cbf33,0x025af085398a5e229bf586fd900bcd192d1d0d987217baafc74f95b698fe6151)),
        TrieNode::Edge(EdgeNodeImpl::new(0x06380495cdd0b2ad24159d4dadf3b814a4dcb3c7f1c0320e7ab557701a08, 0x04f1a9ead7881ae6068230eb986ed7deeaa78f3d0547630e8bfb4650fd96e46f, 239))
    ];

    let res = verify_mpt_proof(root, key, proof);
    assert(res == Option::None, 'it works!');

}