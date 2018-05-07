from mypy_extensions import TypedDict
from speclib import array

kyber_test = TypedDict('kyber_test', {
    'kyber_k' : int,
    'kyber_eta' : int,
    'keypaircoins' : str,
    'coins' : str,
    'msgcoins' : str,
    'pk_expected' : str,
    'sk_expected' : str,
    'ct_expected' : str,
    'ss_expected' : str }
)

kyber_test_vectors : array[kyber_test] = array([
    {
        'kyber_k' : 2,
        'kyber_eta' : 5,
        'keypaircoins' : '934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2',
        'coins' : '3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0',
        'msgcoins'  : 'bac5ba881dd35c59719670004692d675b83c98db6a0e55800bafeb7e70491bf4',
        'pk_expected' : '17561505679effcfc6c0eeba07a070b8dca0ae47e6c2280d7383244c6b0fde49dc429839af497d23c3e073e9d37bd1e00a683fa7497a74ed14d30db66a3690e383823743aa1b29cdf641faad80e73a450095f70f5e0cff42c3f4f3089bf62b4f42d14e6a5a6785d560eb2d57d3ba20e21a6e3cf04001a932850d64957d967f68d4b3afe380a69e6efa8e9e763c2b346bfca6af4042297d1068857a722abec1fa8cf974fe5442305be55e3f2d5c31fa9da2f581775d197e3c3611efe697ebcb12c935506b51b0491084b0f260e77c0da86d01b7ae9afb9d62df81e681132e9fb1260bb4a280da7d418088a0437c465eac43c7dfe27aa931a466c9f4f5817a6317e3d2be29b63971497a3fdff931d203130cbabcdcc1c427820e545bd92f20c1da06f9e1a1e6fc702a76dd73e7614d2935c816b8945cbb80021eed62a74c6558e97010aaf101e6c1e4de642f23fb74a42580ca015cf9f6fa0356abacd966987723598cc6c90d325d0b29cb7ce09e057a824b79369430613f477deaca2e39ec80a85ce6bb06849f43bffcb58a2447fa01176d7347e550487257be11e9caa91e9e08445d9c3602d5bb59d6bcc25939aa1d8cb070c86cbe8ff606ab7ed6e79ac120e7e27550810de69e0a5cf93487e419fed785321b8a539aa9d5d4c4767b3121624c7476ddc8b1c142574dd601938fb805baa8d966dd2d04399f1048299cf3a1c2f5c8829567852cd7ad804ccc484544c0bad61c03fc7346ad1182908b633f96ae2d507a66833cf4cf2b2206c692cc721225d9a5c43064f59db08bd41ef74db36e2445a51d76cdd4ad9708a064063d7352a42c14db3a0b36f02adc88dc04581caccfd0069418888ea8866cd2f99ee17ed4f976137f7cc1a80d84104629f423a0702de74e219226b289bc6f60eb9840f655e530a21413f85c20a1e98123bfec1c3896e2aa178a53d2ea7ecbe789306be82fee4d1def3d3209c019ae64f5e7144bfc23b72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d',
        'sk_expected' : '2ec119e11d6bf4b631b00e17cf0dcd5e1fce7e343cbfa8ab7e088d8b560f37ae8df5eca8e8a5ad0c1b761ed851eb6c19692719a46c151842b3492693aaefa176df39f1fe8888f3c3d59ad981728d3b759b640ab042964403fb18b75a12fe45d78c248d2dc4355cedb08eec39104c5d350b84569c18a43b28711bcb3d2f3154c98531a1c071c0b14d22b050740f61870970b0351037d09e3441eb585e4359301837e7e4138eb00f7edcd371738f067d62db0b338308698f92f5855f847e2c731f020d934b280176e1e4a2a0597517a70ea070545b5f41b8e7a04cde60406697bbf7294ed67e61c9ba7b903135d1564b4c00cec44e5cf3c531d28c499342c166442ab00de12a34c1c9d2a1415e3838557d95c55133c8eb332e31c0ae31c70904fd700df3870ddfc68172490535e43f2a9a0ff77e7c8bb984bdf3dacbf8c7ddce74b7a4623bd79733204e8d0d0a3c62df36f67bfe35213f9b2a936e4288bcc6b452c231b832767aa329456612b46bd79cb0431dc81e3176b4908cc07091ea7194316496ee4243b6d9245b03180f01a9dc415e4514e9971f0fb6ba132d30a25344d261b4bf8eda4bdb08ffa12e45ea8123acfa33af0b406284ae25b84f603d80be72faada627c47d918cfc455b84be6aabe7e0f9e83533e6223177224d8a73330aea2a3e8723358659261a314a1bc9530cee8d383c655d6f5618c9c6cccae2bbfe92a7e18aa8151e2b1f84528b288e96fe2dab76f35838878305bbb171f7edc0e0a6b30bcd09537c71f8f76ba6ca23af694890f2f4181e0304f30628a182f8021dbdd28f29b8fe5d64c00980cc328399bc6ee7e8613eae709c10e404545789688e7342bdba26463044d319db52622711648409c92e1ab89d0d056f8d3f3dbeb82a2e8c4c58b49bcb61260d7d6548117ca8b58c2eb6ad3aca35388186bc406b7376949be6b9eab9275e9fda49daea5e06bba6da4a061b59a67f44af58d23291af5d5883d104d365287b8373e231302f9d34a28681f99448ebf944d40073b171f184a939c9559b44a8e0590840e56ccf935492fb30fb433c69666349d3af542bc74e88578e34ef3ec39b24b81fcce3e15d927416aad9b551e41076a39b317adcd1421bbd1ccec56ab97a1c655c9b14d3bfd8890595d3898939305f278352298ace715517561505679effcfc6c0eeba07a070b8dca0ae47e6c2280d7383244c6b0fde49dc429839af497d23c3e073e9d37bd1e00a683fa7497a74ed14d30db66a3690e383823743aa1b29cdf641faad80e73a450095f70f5e0cff42c3f4f3089bf62b4f42d14e6a5a6785d560eb2d57d3ba20e21a6e3cf04001a932850d64957d967f68d4b3afe380a69e6efa8e9e763c2b346bfca6af4042297d1068857a722abec1fa8cf974fe5442305be55e3f2d5c31fa9da2f581775d197e3c3611efe697ebcb12c935506b51b0491084b0f260e77c0da86d01b7ae9afb9d62df81e681132e9fb1260bb4a280da7d418088a0437c465eac43c7dfe27aa931a466c9f4f5817a6317e3d2be29b63971497a3fdff931d203130cbabcdcc1c427820e545bd92f20c1da06f9e1a1e6fc702a76dd73e7614d2935c816b8945cbb80021eed62a74c6558e97010aaf101e6c1e4de642f23fb74a42580ca015cf9f6fa0356abacd966987723598cc6c90d325d0b29cb7ce09e057a824b79369430613f477deaca2e39ec80a85ce6bb06849f43bffcb58a2447fa01176d7347e550487257be11e9caa91e9e08445d9c3602d5bb59d6bcc25939aa1d8cb070c86cbe8ff606ab7ed6e79ac120e7e27550810de69e0a5cf93487e419fed785321b8a539aa9d5d4c4767b3121624c7476ddc8b1c142574dd601938fb805baa8d966dd2d04399f1048299cf3a1c2f5c8829567852cd7ad804ccc484544c0bad61c03fc7346ad1182908b633f96ae2d507a66833cf4cf2b2206c692cc721225d9a5c43064f59db08bd41ef74db36e2445a51d76cdd4ad9708a064063d7352a42c14db3a0b36f02adc88dc04581caccfd0069418888ea8866cd2f99ee17ed4f976137f7cc1a80d84104629f423a0702de74e219226b289bc6f60eb9840f655e530a21413f85c20a1e98123bfec1c3896e2aa178a53d2ea7ecbe789306be82fee4d1def3d3209c019ae64f5e7144bfc23b72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d3a4128ef22d199eb734a27822df71725e615f356b32d57e5a4302c920f1600bf3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0',
        'ct_expected' : 'd70380f302ad36c4ca0792737ea6c56dc41a2960d63302826cdc3a3cc32bad4b0152dadb20d4294f666e90e007ab016ab9c7ebddeb08716222ebbd82a1a30a810ec5ec4e16633f8619f4c1d55718cd322eb925cd4f619ecd85316ff54c40efb0d3ec8e2f7fab58d1620df78ee81b468f8bf8275bc19488cb455e088f84edbdcc6c20a7c30dcfda2c4f7648086700295016643d8ff33433e97c22ce7be1186ae3c202c866fc974f5eac5c56365070daf7302587c45dd2fc05324d4aa3800221a6bfbf974afca3eea3a4ab3034a3cbceedd6c74838b0dacadec27a40b1041392f9d1ece9d299a1c50bdf91d108ddee9fabf3dbcc2ab7678b7cc7f54558dcf69ea8233bf6175ba38a7f6bff2568ce1f7683cd38839eca48a3ad9d819b42a2132a7d9976431512a23f7f49b923d26bc83a0ddd2322c66691f6a1adc0b1df19fe693c858de7be128693a4b0aa64660ae332aff43deb3e9f4605442cd06578dd15501098434e173eb91965bfa365c06a059aef8667672bcea8b7b596736691cfa6bb414f618350fa5143f68e620dd040ee3f4d0d6d8c6e517c6cf4dea5390d2f346ce5e263e479eb3d650da3269ede9b8fcdac832af2b284e93e23adc9c3ed1bbabe0101a5346bffc6f1144d4bda368252432187fcceb5e726c24edfdecefb565af6aa1270bac7411e633f1b4bc479cfa30979b4507dc9c483a628ff314503243da9dd20b2e0c8525835fbb5fc8de37fbd295afe9d8d50e86703154a4bc1c1553f73112364a8ce2c1f1b9f67fe0dfc47752742c90bb389ffbf950d2e5da6695099b19f5f2eaa8b9099a64b67100b6fa28c28441387c04745d29a224982d4afcdb26c1314752dd51b4dedfb3692e8f0b01ef7e36baf2d6ff7a82607cf57e7df0f81df6bbffe658a487e9dece7a9744cde88760c464cd874952337977f70c4cd6295f90b3279d1f8aa53f68c50edd075f01fb2219bff6814c8ab8d75881c6d6419fbe2ec893033cc9e50f4102d112cd5ed6e08fb7603b669062f436a36f56d4c0a6e7ef0f87371c3a39f66ea67a390153aac7f318cf925eaea400f1bbecb3301cf0272dd914aa9f0e2e282f09445e23b018c89f09b9ee2084be00d97e4970210aa5060b7',
        'ss_expected' : '9f853c2220e2137c96f4997e841e39f4c563c000d1d6a82e8555edbd146ee15f'
    },
    {
        'kyber_k' : 3,
        'kyber_eta' : 4,
        'keypaircoins' : '934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2',
        'coins' : '3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0',
        'msgcoins'  : 'bac5ba881dd35c59719670004692d675b83c98db6a0e55800bafeb7e70491bf4',
        'pk_expected' : 'c9f9afe72e604b4d6b0340cb4350aa2bfad9c675e34ab4fb8c4aa9f35540a6b2f0aba80694ec91ef515587c3a72bb90a091d21dccba69cef9a2b65d9fd2d0e011455948499ae6f2eeccdeda3dcd357ff573c7bedbb9751d469b9b0b5f8ded1cf26ce963b549b52a20b9ea514603943412f8e6cc3eeb34268861eb117636871135063bb9977f5ed4dedaa35650f717ca0785ff78dae11a44450379cac65b1fdbc74c823d83de3bfb3084291dbfd85f4f2ac3687d03806b550f4ba6ad9179e921b4fca0a9b33eec6689d23b86a1b4c0e1c6622b2fc1da99735f2ddc94256411662dd3b2231c33cedca3f515863d3fb58561e3826a5f544d5af3ea436f98bc486a47d62df8c298f257c4fb3927245918376ddea4cc0794b6f5e15e572fd9d4860c458401d951992b804d555270ad76b7f6dd6caca367c8d262ea6c66535a1165caa1c488d22ba7c725f6a5c19f32ebc52f600730c96f49c839b513440a5c915e9dfa90401cf95dbe595e9b885fad7d0fc5abd501edcf06f3fa8733acde7252b6e5b51433112f51269ab17bd0f73d94d621c2bad41be822f1444bcc7efca9478d3c0452de7dc86567d304985c1123ca097d2d07f65d863e664c62480081717f5fc04079c02561c75a902978c55209599a6c4b9d71be75e9b8dcd17629931d540f01478f25e12b52609988eb8123a6905380ccc74af9d690a5e3da5b014ae146ef9c225c13f392566d61e73751a49374c56884c788af869264ac1cc1c2db11770c751e8ffe1c7667397328894643716832a37b79d246e5440d4b1bfbc06e19b7ad4b90b593357756dc9f1d4a8807d8216d2c6f2a22a5eb7f28d7db249ada72f7d70c579d9a65d0431b61b8f63da5b83dc1fba81e2195e698dc7522506643f635b571dcfa5584e1e3b329e27db5964afbceaa569d51c615f38a6d5013f1b2b8f0fcf55476d7ff0b69cc1a52f181b52981d5eb163d2ad7253c029cc463a8a5b33963ab33be42e8a6bb83d3cea7b11308211efcf324032424fbb3dc8feb8e27c449d53c1366ff52cda0ba99a7529ad90c8e2e18b80bd13521b62ec1a0dfac61d8fcda2843eea86ea00b52c1697cb4fc1afde71ceafa07322486083514e335a9658a08da1b8002d2e46f456b4e32e82211167c250b398a1dbe6f8024b02315379363486ab70977776b898b84e87f8a44091ae02554106a515c836c6424e26cb0f20bdd2c58da14f6d16a7770784834d9b8d3a74877559f89962750985337be5f66e4deb73cce2db059e33684b4de2938697b9203092b5a0ee72b6e1cb15013aa7eba34b657df98f5f5e8eb8d7b47da59d86a2067bca9ab1055ac8ca3af8f654f881475fcf246885ad131f7eb9abb153f0c9d05194490bcc47c6d905eb67035eb7148d99b477b9df879018c68d3435de554962cc34401dbd6b13a8f2e33dc3c5f60b82d160a512458c00401256fbaacf50a929ae59e1cb61cdacb9ef681543b751f99306fab72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d',
        'sk_expected' : 'b78e1727bd86310a6cf095c66b2febec495099a426e93893cb665c09d35272e126b0e8505aba1ad1c12faa7296467594a1a2e9c09efd0c46577d59b19f2bbccbae99e3bc6061f289e0240e93fbdfb04d364aaade190476e7f4cd9e2f159c907280a34fb3bbdbdb3e668f1640951db9b95690e0acbfa8029bdb21a8e7523fda9c2bed931a4357ecdce214b3e4ad620d49536f87a47eca070797e9b1d2a001c5c4942ccb92f47a92968bafb79319900fc68ac6fba5f228ffef46b74d49e63464513979c25bb89ff170c6258f9bb51b5d528a2d31de844fb4abadf206e493be224cccc474b8030f043a6daeb214774d9d5bcd7bc1a22ac01192703f888dc61a9dcd21a7905f81f261a241832d3e0244e73d40601d2f2e66fd22536f1f28b88d9bdca14755f9ea336b65da790af5043aae254162f2626a40f047e0db78800a0c02ddc07ad3d621d1668642dd92cb6e92d15b9b12fe302f28e762996372c1c0469508fa2d7944de3130cbe42baa94dc164fe5e8235a7db3202cdf3e85075781c54ad438626e1ed6b132a54c0af39cfe014cbba7b2608713d90e3a175acc8b0bd88389075816785737cc3d49b7a5d3e0ccd8f04d3ba689524cad0b89c0f0a15d1b9433c8c4ef9e501f44b4e3a671422fb05b0b60d90a78eb6bf39e46499117435e9ee633c317e7be1c67629cf26f8f40e6d0d584fc3b63c1f5ae61378898e30ccfc422cc49d38280e66bbd4f13f230a1e240957e276bfddb208c8e069b43e163f4285cb518bab1e70e87020d2e5b3413394d73712302bd8876753eda3a6c270c8e9315d00c6819d020981a1900c4a0375549a978e6c824c67a96a74877b5cb61986fd469f91ffe0b966b70214c9b7483bb3814d2bb561b68493dcdf21cb061516889a35ab7da6ea3d34cdf3aedb94e60ee9e939695c2b8d23a71dc434c86a223d7db67245fba65030085ce48c84e1203a2b60b720d4a6a3662997d61be910dc19307731abd2e7cbc2b9c44b7ddeb77b51097e561dbafa51b36e04439b181f90bc710bb1b0dca96341ef5d312816628ce963a340b61a04609d8553ba9af744063371e6ae22f5d3b95795f9d18a68455215200386d8c4dda72ef382e28ce889ced0086741979817d40af5da5c2c22a06f10d4106fec4c58c570f4fed607a38fd775b191b3fe40a81639b5bdfedeb439a7c1a06fd826e0744db45ab70424100b702b19ecbd03b58d89b13b609280e18afc8833e6bd5fc78ad84b2dd2cc811a21618c9a0f47f6d1ad5ce1e1eb84be268a6ecdd03bd1c311cf22369912671d4b0cc1d755662138090ec82803c147f51a995835f0e4873356eefac3b1755b8e4f020a95c9b53442595f856d3148f05b00a53a739e3ea963760ea21ec86fc9ccd6b50261b26df0d605589c3de04cf762742b9b4e8a42b6d22b0d12a71421b3dc0ba7a882bd688bd5dbc11b272cec088b69d3b5982431d5b18890b3ac478ba05d5d2aaac3c3b2d9610bb0d40e05070425810e6941a66964bbbf5a63cf826fa39b3f05a9cb3a33af35521a4117624bb38067bbd6430bf1156f9061d16d0e45e112a63f2e64055364dcbd897faa68ad19ff0420635aaa71285db9d7c1472cd2e5a7a5a87436d6cb1c3d50b4f00dc7860e09d7328a571f753829916e64cb925f55bd234adb5dd0f386169d150817c21a51160e1976d4393e6aa7c1e4818579bc871ef2d05dd620f8eb3e5531f2c272d923e1498da7794801427c3e867c83a50840bce7c5e5a0ef01cc9f9afe72e604b4d6b0340cb4350aa2bfad9c675e34ab4fb8c4aa9f35540a6b2f0aba80694ec91ef515587c3a72bb90a091d21dccba69cef9a2b65d9fd2d0e011455948499ae6f2eeccdeda3dcd357ff573c7bedbb9751d469b9b0b5f8ded1cf26ce963b549b52a20b9ea514603943412f8e6cc3eeb34268861eb117636871135063bb9977f5ed4dedaa35650f717ca0785ff78dae11a44450379cac65b1fdbc74c823d83de3bfb3084291dbfd85f4f2ac3687d03806b550f4ba6ad9179e921b4fca0a9b33eec6689d23b86a1b4c0e1c6622b2fc1da99735f2ddc94256411662dd3b2231c33cedca3f515863d3fb58561e3826a5f544d5af3ea436f98bc486a47d62df8c298f257c4fb3927245918376ddea4cc0794b6f5e15e572fd9d4860c458401d951992b804d555270ad76b7f6dd6caca367c8d262ea6c66535a1165caa1c488d22ba7c725f6a5c19f32ebc52f600730c96f49c839b513440a5c915e9dfa90401cf95dbe595e9b885fad7d0fc5abd501edcf06f3fa8733acde7252b6e5b51433112f51269ab17bd0f73d94d621c2bad41be822f1444bcc7efca9478d3c0452de7dc86567d304985c1123ca097d2d07f65d863e664c62480081717f5fc04079c02561c75a902978c55209599a6c4b9d71be75e9b8dcd17629931d540f01478f25e12b52609988eb8123a6905380ccc74af9d690a5e3da5b014ae146ef9c225c13f392566d61e73751a49374c56884c788af869264ac1cc1c2db11770c751e8ffe1c7667397328894643716832a37b79d246e5440d4b1bfbc06e19b7ad4b90b593357756dc9f1d4a8807d8216d2c6f2a22a5eb7f28d7db249ada72f7d70c579d9a65d0431b61b8f63da5b83dc1fba81e2195e698dc7522506643f635b571dcfa5584e1e3b329e27db5964afbceaa569d51c615f38a6d5013f1b2b8f0fcf55476d7ff0b69cc1a52f181b52981d5eb163d2ad7253c029cc463a8a5b33963ab33be42e8a6bb83d3cea7b11308211efcf324032424fbb3dc8feb8e27c449d53c1366ff52cda0ba99a7529ad90c8e2e18b80bd13521b62ec1a0dfac61d8fcda2843eea86ea00b52c1697cb4fc1afde71ceafa07322486083514e335a9658a08da1b8002d2e46f456b4e32e82211167c250b398a1dbe6f8024b02315379363486ab70977776b898b84e87f8a44091ae02554106a515c836c6424e26cb0f20bdd2c58da14f6d16a7770784834d9b8d3a74877559f89962750985337be5f66e4deb73cce2db059e33684b4de2938697b9203092b5a0ee72b6e1cb15013aa7eba34b657df98f5f5e8eb8d7b47da59d86a2067bca9ab1055ac8ca3af8f654f881475fcf246885ad131f7eb9abb153f0c9d05194490bcc47c6d905eb67035eb7148d99b477b9df879018c68d3435de554962cc34401dbd6b13a8f2e33dc3c5f60b82d160a512458c00401256fbaacf50a929ae59e1cb61cdacb9ef681543b751f99306fab72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d86be97871b745b34e2dfd72ec27a97e03be0f265aaa2724f84d9d1999ba5a92c3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0',
        'ct_expected' : '0741a7f88dcacce1de855238f4493aa5d693db59a17443c05f58770cc7b9e1309f69382dd61b5af193aee36ed8598ffe963576be93d5083b1afc6012cf37fb6f42e6f444c5be06f6db66c2095cab54140f7758b2f33cca91de4cc28c6da4ccd36587a503ee1b90462470d4b1abf017e465d0b247503e0f2731dd10d4d65faa85e98b513014963504b36ea50dc06b865416db8b77827922225ca26a80e4329b765c725191d247c4d94e52a1ec619f14b18a0514fb1bec02b5353b5f8246578489b616eb8be75b38edf5e2e05ae194ee571b689f31564183bac2d385f416534ee93b70306ced7532d54611c96ff6a6fe6f68305933a14dff753b316030f426b5390d3f726e117cadc44fc12e6f2bfb1b8578a9e36724ed6a23b96271b924fad406035de6a020d4ce08602e7086832522ec748d3cdc9403e89c085ba10be451cc1f2a34828ccc2a558c5f02b340bcb4a6cfc92db4644d01e948f164444a669bc179c122bd6771a7ddcb17ab271e7fa0fcbc5f337544f791fda5f13dc36ae564331e5be78870114c0c7a007ef17c5d7f6a8dd7a99ae171bbaaaf4c331a87cde7913a5fdee4bc6b09f3a19e75ea011caf29bcd4ed1fb38e720a2c7a0d66a3bb63a9f9855d996cf867477311228dc61ab1daf808d4daa1ea9f27ae1fa2a3af532fc90000a0f707033d943b9110daf2be5f62516ecafd358ca4786f48a9ea245d16310ec9617055577552647785f2bbb8563ed838bd696c8f0f9432a558bdda6e3991445d2b5c0f19f4f7314f31333a0b8c94781307c7d06a0ea967ead28c37f45bb7a86308d9b9c517a670f23b4caac60b58cecbf8b4e0ea23440a52f09f0197be2a4df96eec07a67dba0d68723253659cabf4361949d1734d182c2d7c72bb9f647b5c36200522770275f00f9976b42b86a77dbadabf392fd0407a56fb4da158086c0479239f8fecf70eee42137340b3186809e97a8615dd1cd85addd14053d127a1149238068ba7aebd43d849fde8e0e95d02ee9cbda678ce24cad0da8a942bdbfb565462c6de7d426472dd7ef2649b44fbfd113b78d3e75bac946ec6efa509eda549a90f7846c990900a29874c03e0d84116c2fbf0b5b9eb936afb9c54c6f0ac66a5c32e1efbbc1b56e02485d9333013f490a4120ecf976dd0c1b7c0dfe9b7f700bd6822faedd32aa75e465ec92d0512ed15001e153e53e510f237ac3436af1667b6c4520b40146fada99ca8e27a42315faabe14ae1e703894694a4ec8d7655f7baed5ed314a07a8f2adc4be1ab573abbb613ab740d546e9c5e04ecf2c7c5ac649bdbe7041eb0e3f508afb02cb9e923ca0f843a4df30fd7957e5f13966542d17e0c6101b25f21f2b2374237c3368303c7539c89ccc798f372d95ba41bde6f403abb85ef9436a6afce02f0ac74074e9356fade7c99c60a2b418a5eb6296607e124edb52694a85a0c13092d9cea9025b2736b4f5da97156ee5d6e8385957f221b39cd3baa6066bd4856e8ec8da7791314a73d802282d3c95d6e37ef358c42de500b8f138054dc86d0799c527f19ec9bb5de4721b025b2217f1047462cc1437fbacc909852ac754bc8e91d4e569a69807f82c18756ecb39be6e7d0e00544b14bff24da4',
        'ss_expected' : '23c7a3ae29223b8114db02fa5cf8834b11e48fc55e69534b032a695516cd93ee'
    },
    {
        'kyber_k' : 4,
        'kyber_eta' : 3,
        'keypaircoins' : '934d60b35624d740b30a7f227af2ae7c678e4e04e13c5f509eade2b79aea77e2',
        'coins' : '3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0',
        'msgcoins'  : 'bac5ba881dd35c59719670004692d675b83c98db6a0e55800bafeb7e70491bf4',
        'pk_expected' : '3d922a46d60ad3219de7164d1f4d331fcefb0821145342f7808c872234dcfcd5ae72bd57c4bbe1cb309cf844a97b6e4dfaa0a993d3ae77d1b44504dd5bcc4120e68d8bcbeb21bd93718077bf760213674e0cc96c1f32c026b113460ef984906d031ba48f0d07f60f40e5b5ad0e20a4920bd48d4a43dd73465a2c8c75fc6f86ad4457d51f33bb082cb63154f92d4139bb7cd22774c33e9eec90c2afe3f4fd35e324a0041b635000c3d6e45d1ccc0d0fb424b47a648b57b67955c3d4d8b01383d4caeac708509b470bccb3f1b562fde1950d78b51fbb5642c902d6ac8e1ab211824fc19c2bd424796cf4852dd281f3f5cc9a5f1672e8187be9b974406517f7c420c0abe1e649d3913afa6b3fe377a19ac256a68951b3c8c19ec4067d08463684d4324c40581c12b962853fc1605e65627706ffadd8301cbacbaad2ab5e4115bb611f9171994a8d9d712e8fe33f4b03e2343af2fe4934306207057dbf9c333b2aadf8ff1763d62a1ef9fb7a189784dee62713d2334738e71aaa7531f08aa358c3cdc4147ec08981318fa529a4c9b8239672007eee2dddc0e6afb04d321d1a0ad2df7a2fb8c623ac77a5ba3c546f48c8a2b5c0d740f7662ff3cc887b105896e8f0e311be41b2df06e1029b3a821e2ab06820ee4fe45523467b24d65157b58145f11ac49aba23b767ab9ece613950970c4deec737dbbea49794abda3f01816800363965113bb2f25c45842eb4ad7f896c3c8836ee45f6c600d78702af6b7ab0f1e1a99deb97f5f58cb207e53fd0ccadb2f3d8392b8c6fa282155e0da700e16f71612eea65806e72e716ef3fc5811e3d3fec407821ee56e8ebb7266ed0eaa0b9552ca682235a2c655cfd3f1c466035989f6e837a0662e7fe977770cebd44ee9104a7092d59b1cbad359e5e38903008c002a7db201ed915f23884bdfbd976665ce714e483dbf0538f37bf08172846ffd44c4afd5e75addc96bccd05fe88fe4154996f75c91da0da95a237f349f495cc61c68221db7d4252b63ab6e728b8ccf9c5264a3ef93bc9b1bda40091ea929796e5463adc23e68c0114ba652c53b37091287b79110770fdab402308d6693c6dbe7770688d8c010de4f3874e1dc5d9de67f659da38ffac217b2da0c8032dc063503ef56906f33e421e721bbfb3545d220ea993f0cd681f59b66b4470485b801b3755d3b8af13e6d3a45b73ba67941f702b076509eeaa4a37b49713b851a68fa09831915fb73de0b0e32ddac48ae367f43f2bd03fe580ac38555cc1138ac490e2981058b96c0ce0049cbb2e04efe760793ca43a92306d1db1a022ce420f0518f667311fa3063533fbe4a950ea146d2f7f95870e3fe618e2c46802f287dbc49ba3bf6c19d48b06b61182515fae65c803a920c591188fb251e034364286296f744c1932d52a65b5400b83770ead737d6538a762910f4e4be0ff11e0c0aa6d92504c084bc7af8aedcfb64c094994a924f807bb47c4326b047c9e8605b682d6cd302d80732f31b03f007361c9c261fea69533e07259d78e96ccaa2629d37aa9539e70002e975f2db0aa9813b50b52712c787ce1624427b9e3960e72bc150f6ad5e20971aca38416a35417bd783451ca51b8e92753eb2b6bd22edd8f3f73681afddab4c640f4cac0d4e27f79c883e8aabe8a3abebdccfd09b94eb78bfec7a0bd1cb6c71eebcfb8bd30cd0501a2f9db1e5bc2c452668319ce7f047bd5504aa9662e07d34101b4edf02b4f5f62e845a5f27c7498364263132d9d992bbced599fed790c850676855afbe24acb87114971808e222271b390062b7f4e94e23a02a3da66af93ebc3b3a7b809faeed2ac97b113a4f463e79c3054626b2acae586dfe9d4974c337010c1b4dae8d684ead7a2f1f59076badffcafa678536d05c8b21db54ce96170ddef0b4153a7ec444582af5919df4965c6fc4b3cfab0e80744304045e287c356dd24e004fbbf70031909a8d9c03d246b465d43caddb72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d',
        'sk_expected' : 'ddc94ad1e5d92281ac70e18e40f19b20700d77569338cfdc56be71bc32d0be125c953721b391b02fc167fde40d304acddbce5082b2f659a277fb2321d2965689d29724fd1457d8bc1f891d254338f510315d068d01dd91e16aeb28fe378753f4f293ae93abfbd1a1a13cf9196d59c6123780c59a3def315fcf85ec61de84e9d02b3afdf796e540087d3a109fac69aa75a1f240339fbc298345df726c3635d1b6007133ca8dce259a5118f330313630d5bfeae82a4d22c1d93fa48954b64b68a64ae25f62d24cdbd65d314b8a4bccbe99ab40bc051061dcdb3d068186c3d7b3ea848a4a997ff82535f43621d5d7c037f4ea03e6c83e58e7d5804a00569131d2ee4795101ebd1afd76999b76c0f28e535d5588d538a4b9964ad2172d759390549a6e558e15d5c1adb712507c0d5216a3581621467288289c67480c4c686376795bad7a160c780fadf00a3096d2b5d1a87e2bbfd3c974cd9ff0cb37198466455caeb57f699921621ef9d365911e9ddb76d3a52672a8a58426ac4a5ef4c5cc5e919c327a3495b6b8a489e4ee77ae547df70b38c14acb6812bbde506c4f25f0da7409f8504b7222b8da12d1103804065374a3f6dd42c4e278a979576ea9974239eb76d9b75348fc1a6ace4d3e0d23dfbb020b5b7948dfc9b48dbf437a46c9f21a5ce8180d09302835658eed120d86f94e63e8ecc1664f0831dfd506423de976ba073850bb6719ec8dc18bd6ce47642c3a686b739a8755b9aaa6892f11292e4ed5a77cf829c702e35e471421844d80a04991ecf26803844d565e77f93527b7b8bd3cfe92b2f488354058c38164b51cc218017233217507a5a66cf70d9c4a35683784b70753e936860aa634067cc56dd4d696a187a8464c04b4894838d74ebed674939fb2b293e859865348af2ba8d0b5e667d3c3a4a23703ae7980cc455ae0edfbaa7385e12b241139d4daa7de2c64c8a36588a0a1dc41ff8ebd661d665ebac42b636266a69bd47b27fed05d20e7adfd08bb52b3a0b0f69c19cc6fba856e3adad04d53be63d90e3ace23c91a40c6e5333390128a08d0a212be8fc380d7f3c481a50133b44d57aee2a475b874517e9dec98989497c8a6df65a34ef09eb1c26b1303b4002fd984d841343bdab81ec81c189c839cb4e1c9e976af9f6eeb614812a109df0e3af6f3a2092dceacf3939ada5ba54252eb5f11ca47beedfca5268f816ec191b75b716b600b742210471984efcd142fa813774802c7137fbb0be6609fa07547dbad5675332e6426ecdbfba78a228676670e0103a5205f1131f25935e8ddc064c9430beb4e1a29c8c10f8f61a15dd0dd54692144ddd7a7efa6584068de0927dcc72c04833b29a3f345d257ae3a9e5e2d187706203706889fe84d6f6aa9cc0097c49abe34bc10c8fb4337beb19787694c7bf68cb944dd6114c04cd73f7ba07625b49c01f0e2d77c8caa36433c05aa53df23ea90ffb6caf2e719d4e9da3dd137829307b1b7ea12a8b43309bbf966809b72a409f5baac7d7b9c8827d295580c2c8bdcdec57baf508c7864d44cd1c4dc8701bac12b3b92acc582a7881cf874c0ecef2764bda6a655188873d6b98e96dd83cd50dab070b526f218c5201162d2dc466e6478f1ce310b5bf98fc42ddf43d092644d612578dc005e981d3e757e2debbe3f7f2b1a4530562ea50400f629d5765b345c83dc9c24032e1d53b3d0d683a40faf3c5f237683f0ec00cd011362418608631c814ad45db878ad15e112d561a83acb22db2873846468db52b9809a00e3f82d40875d237da200757837b6a58849f1564eb9324f75d54904725d67e8a22a91cf98e89a4449ce04242d943c472369ec0db5a58f6b80bc4aa18b55b16bc88e01c55cae2a3efd614bbb686a5e0daaa5bf61c1ebd14a4c8321c022680043fcd2cde8e26ccd0d383891d2111bf555385f645b2c8e2c079c6f11c0de58e8b4a75bee1096c92a57201f1c652708e9c4231c9940fe4d4784b034852044600850f66a7774901798afca3db4d1a6a759d19eb28d8c9995395eeee9d8fee062790d491c1daac77d8cea6e1e6969bbda3580d9629660cd8a8bda3dac51e1d2a5347a79ad783afa63c3d429dc3d4f24f84c12d2dbdb76f589db265e3d96866020f52917231d7ce9393528ec74af13c31808d34284479e46358d46e4c37ffe2ff83394ff5647e3e11a9310772dce7e17c07604966ff0b66d0a7035f3853171740d8889c9331eaa2ea149efea900b666c39382ebbc7b632d1e78562be435d68ee602ea0de617047a24f6216060bd2099aa66d94031cbea57765a05338b008ab1990b2cff0b5158fc4734389da5724de3c2c8d46d1e7e740093d922a46d60ad3219de7164d1f4d331fcefb0821145342f7808c872234dcfcd5ae72bd57c4bbe1cb309cf844a97b6e4dfaa0a993d3ae77d1b44504dd5bcc4120e68d8bcbeb21bd93718077bf760213674e0cc96c1f32c026b113460ef984906d031ba48f0d07f60f40e5b5ad0e20a4920bd48d4a43dd73465a2c8c75fc6f86ad4457d51f33bb082cb63154f92d4139bb7cd22774c33e9eec90c2afe3f4fd35e324a0041b635000c3d6e45d1ccc0d0fb424b47a648b57b67955c3d4d8b01383d4caeac708509b470bccb3f1b562fde1950d78b51fbb5642c902d6ac8e1ab211824fc19c2bd424796cf4852dd281f3f5cc9a5f1672e8187be9b974406517f7c420c0abe1e649d3913afa6b3fe377a19ac256a68951b3c8c19ec4067d08463684d4324c40581c12b962853fc1605e65627706ffadd8301cbacbaad2ab5e4115bb611f9171994a8d9d712e8fe33f4b03e2343af2fe4934306207057dbf9c333b2aadf8ff1763d62a1ef9fb7a189784dee62713d2334738e71aaa7531f08aa358c3cdc4147ec08981318fa529a4c9b8239672007eee2dddc0e6afb04d321d1a0ad2df7a2fb8c623ac77a5ba3c546f48c8a2b5c0d740f7662ff3cc887b105896e8f0e311be41b2df06e1029b3a821e2ab06820ee4fe45523467b24d65157b58145f11ac49aba23b767ab9ece613950970c4deec737dbbea49794abda3f01816800363965113bb2f25c45842eb4ad7f896c3c8836ee45f6c600d78702af6b7ab0f1e1a99deb97f5f58cb207e53fd0ccadb2f3d8392b8c6fa282155e0da700e16f71612eea65806e72e716ef3fc5811e3d3fec407821ee56e8ebb7266ed0eaa0b9552ca682235a2c655cfd3f1c466035989f6e837a0662e7fe977770cebd44ee9104a7092d59b1cbad359e5e38903008c002a7db201ed915f23884bdfbd976665ce714e483dbf0538f37bf08172846ffd44c4afd5e75addc96bccd05fe88fe4154996f75c91da0da95a237f349f495cc61c68221db7d4252b63ab6e728b8ccf9c5264a3ef93bc9b1bda40091ea929796e5463adc23e68c0114ba652c53b37091287b79110770fdab402308d6693c6dbe7770688d8c010de4f3874e1dc5d9de67f659da38ffac217b2da0c8032dc063503ef56906f33e421e721bbfb3545d220ea993f0cd681f59b66b4470485b801b3755d3b8af13e6d3a45b73ba67941f702b076509eeaa4a37b49713b851a68fa09831915fb73de0b0e32ddac48ae367f43f2bd03fe580ac38555cc1138ac490e2981058b96c0ce0049cbb2e04efe760793ca43a92306d1db1a022ce420f0518f667311fa3063533fbe4a950ea146d2f7f95870e3fe618e2c46802f287dbc49ba3bf6c19d48b06b61182515fae65c803a920c591188fb251e034364286296f744c1932d52a65b5400b83770ead737d6538a762910f4e4be0ff11e0c0aa6d92504c084bc7af8aedcfb64c094994a924f807bb47c4326b047c9e8605b682d6cd302d80732f31b03f007361c9c261fea69533e07259d78e96ccaa2629d37aa9539e70002e975f2db0aa9813b50b52712c787ce1624427b9e3960e72bc150f6ad5e20971aca38416a35417bd783451ca51b8e92753eb2b6bd22edd8f3f73681afddab4c640f4cac0d4e27f79c883e8aabe8a3abebdccfd09b94eb78bfec7a0bd1cb6c71eebcfb8bd30cd0501a2f9db1e5bc2c452668319ce7f047bd5504aa9662e07d34101b4edf02b4f5f62e845a5f27c7498364263132d9d992bbced599fed790c850676855afbe24acb87114971808e222271b390062b7f4e94e23a02a3da66af93ebc3b3a7b809faeed2ac97b113a4f463e79c3054626b2acae586dfe9d4974c337010c1b4dae8d684ead7a2f1f59076badffcafa678536d05c8b21db54ce96170ddef0b4153a7ec444582af5919df4965c6fc4b3cfab0e80744304045e287c356dd24e004fbbf70031909a8d9c03d246b465d43caddb72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8db2d027b91c95ef02667d00bd88c6b68c5d25a070e574560344ac952dd061df9e3e2a2ea6c9c476fc4937b013c993a793d6c0ab9960695ba838f649da539ca3d0',
        'ct_expected' : '75e0438f2d90a7f29f3aa4ab0aa56c71dc2079c5b89970af773cd675c394fabb8fe7230ab8ee89bb60f7ceade53cf57916f6adffdd83f87cb430484c1d84f75d917a46c77418a13a2fd42bfe2c3b403e530f3467f011671e9cbcb7c8f11ecc2854dec81118025d9f0a39da83d055e5873de45afc3fdb0b2841c16f512db32803ad5b59bb789238fad4d5720a559d28465718d388e11a69a7029460748722abd13957291b0c452e19fe03fec9d9992034639f852cde269e246bfe2b9d59958ce1fdf32c33552f6e8340cdb18848fdcb238785dcbeeda86a4a426ae91f52322f27a8b8a2115ad4d45dad8768822fb49196b2715f1af1fdc7333906ea877ed18eb7c82f95c0d0763a994e1dc32f19850bdd8e5176ffbe4f468eb7a41d3f85a935225e4233aab1fee6338a1c0cf80029f81c8e8c700354a4ed7bfe70060fa45c6b19b48df032fbd5d97c266131bc1bfb561c6a008db41494a6a2ee89a093313a6067b7dd8c3dbcd5acadc8a4b811e33f983a6240f30368770bf706127a3b1359f0c67f0318b257cbc257e52c48f1cfa05e6310f141b13aab8dedf7b23514e8dde5cec96db9b849e6682ff153b00ff9447ef48c1deeb81ad29460645f78a4858587ad39c58aa93ffef8ad88fd75213dc6b2164bbd17d7a5beafe56c36b8f9c486559a897f4f011f11b50337b7e63542321ef537159aeb8e801b2513d346ec8528fe22b1383b1bf9a2775cb685ca386fa7ec4ec0cac6254354dabeefea29bcad4ce224a8772b3694a8dc113f34d5e7f0ea8847c3383697abb990f460e24285ad3ab7522b3ed1b40ab5867040df1ce4fde93d9a96592348433e9388abb70d42c6ec64ada41e82d18df2dbdccb9477a9da9329327caccc7a4cd89aea8af78c7278785f9ba95530fe617a6ef7106466299337a1844c8aa30110c1504a768970f33ac51567819aad4ef7c49597b63cced2e80282b27a8f1948437d6829b651ed7086d4d4d68b62491e265cb697110b9091186af3d11f607172e8f3df38d5bba79bdbdd8cb5606107a15055bafdbbd544f8fcac33f96db4ec353948e08afdca484dd41637b9aa6c913282ea6ad5da3986fdc94ab29b2a8c805887f9aa4716204b24f25fb438c831ccb0ba4d6d2e9f488393d5363d2e163b6dd4ed9211756d1c1070cb2ce85650532832f7593d1731691651d71f4a25df01b2f6023dda837227f2ddc8ec6f759202097e1c2e1e8b5d7f5bd7c22d8a36f6d7a8c5cee42e69bfdb27d7495c6d83e12c3d2d071c34fb0e55b0006d57a75331537fbe14a7c794cfeb32f02cacba8088b6f83fc2266258cc634ae8e9bd85fe5be8ddab9229033973f474b48f795753b6cbbd023a52fa2e757bbcd68d04ec1d760d56f82d77b02e5b35ca2ee2f4a403e9f3791423d91b9355c7711a7b31f3d6c9c22e27e29609ca136dc1d3148374d9b43cd5ff75b813b71f267bb89f4d637872ade284bb155fa5aac896960dff01d521abb431196382612d72eb0e4f0654861bd8c72b1ba5b2fa8b91c17eb26186958791683db5ffb13e038fe8b2e514b5fae0f30d049f94c00f72fd1aa46e122aab439510661de5c6c6cd4e118829e92e4c9476d804b24c08029f6c98f1facafbc5b771113440523c5e2c56e007d62fa0c820b2ca1c3afe7f14197e54aeee93efa7f702e872ca645367850ad0c07ad1a90bcd077f76498524e38c6d3b1b00b0c4af26d8ac508b7de1eb1c8e56a3b31012bdaf3bdbaa9cceb3781585b2448ad9275c61d8325e44952aa138e56f5054eb638b80a46a82e041ea5b7adab60831851c158255f31d057f0cdc34a5a42317cbbe955614db0328e659c63aa3eeb69a506e84436ff38700ba560f96b886fdb192dee0f2504fcbc04d430b5f83e4a1500c3236854c7e90075b61e24e7910e06e00cbcc8732996f6541d618da90592093027537b2b588315d2b79edfe462ca417915d88493ab4b5793405dcc9353c15a6282862388916d71c1bb4ab76ba62c753d737bf2acb203c21866f8d6ea6da273fdef66795375289ec2a219b153896265c785ed13ffa9dbd767c31c9a0ebbddbaca10fbc7804fea6e977a4ed434bb66749b945b7db47af569acb43908b9b42ed896b5ffc',
        'ss_expected' : '988e74abd1a64f07d961c8a37e1d342fdd2a38ff32ab75aa4f89a5eb73bf449c'
    }
])
