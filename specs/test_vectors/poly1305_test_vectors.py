from mypy_extensions import TypedDict
from speclib import array

poly1305_test = TypedDict('poly1305_test', {
    'input_len': str,
    'input': str,
    'key' :  str,
    'tag' :  str}
)

poly1305_test_vectors : array = array ([
{'input_len': '34',
 'input'    : '43727970746f6772617068696320466f72756d2052657365617263682047726f7570',
 'key'    : '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
 'tag'    : 'a8061dc1305136c6c22b8baf0c0127a9'},
{'input_len': '2',
 'input'    : 'f3f6',
 'key'    : '851fc40c3467ac0be05cc20404f3f700580b3b0f9447bb1e69d095b5928b6dbc',
 'tag'    : 'f4c633c3044fc145f84f335cb81953de'},
{'input_len': '0',
 'input'    : '',
 'key'    : 'a0f3080000f46400d0c7e9076c834403dd3fab2251f11ac759f0887129cc2ee7',
 'tag'    : 'dd3fab2251f11ac759f0887129cc2ee7'},
{'input_len': '32',
 'input'    : '663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136',
 'key'    : '48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef',
 'tag'    : '0ee1c16bb73f0f4fd19881753c01cdbe'},
{'input_len': '63',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : '5154ad0d2cb26e01274fc51148491f1b'},
{'input_len': '64',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : '812059a5da198637cac7c4a631bee466'},
{'input_len': '48',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : '5b88d7f6228b11e2e28579a5c0c1f761'},
{'input_len': '96',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : 'bbb613b2b6d753ba07395b916aaece15'},
{'input_len': '112',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : 'c794d7057d1778c4bbee0a39b3d97342'},
{'input_len': '128',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : 'ffbcb9b371423152d7fca5ad042fbaa9'},
{'input_len': '144',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136812059a5da198637cac7c4a631bee466',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : '069ed6b8ef0f207b3e243bb1019fe632'},
{'input_len': '160',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : 'cca339d9a45fa2368c2c68b3a4179133'},
{'input_len': '288',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : '53f6e828a2f0fe0ee815bf0bd5841a34'},
{'input_len': '320',
 'input'    : 'ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761ab0812724a7f1e342742cbed374d94d136c6b8795d45b3819830f2c04491faf0990c62e48b8018b2c3e4a0fa3134cb67fa83e158c994d961c4cb21095c1bf9af48443d0bb0d21109c89a100b5ce2c20883149c69b561dd88298a1798b10716ef663cea190ffb83d89593f3f476b6bc24d7e679107ea26adb8caf6652d0656136812059a5da198637cac7c4a631bee4665b88d7f6228b11e2e28579a5c0c1f761',
 'key'    : '12976a08c4426d0ce8a82407c4f4820780f8c20aa71202d1e29179cbcb555a57',
 'tag'    : 'b846d44e9bbd53cedffbfbb6b7fa4933'},
{'input_len': '256',
 'input'    : 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
 'key'    : 'ad628107e8351d0f2c231a05dc4a410600000000000000000000000000000000',
 'tag'    : '07145a4c02fe5fa32036de68fabe9066'},
{'input_len': '252',
 'input'    : '842364e156336c0998b933a6237726180d9e3fdcbde4cd5d17080fc3beb49614d7122c037463ff104d73f19c12704628d417c4c54a3fe30d3c3d7714382d43b0382a50a5dee54be844b076e8df88201a1cd43b90eb21643fa96f39b518aa8340c942ff3c31baf7c9bdbf0f31ae3fa096bf8c63030609829fe72e179824890bc8e08c315c1cce2a83144dbbff09f74e3efc770b54d0984a8f19b14719e63635641d6b1eedf63efbf080e1783d32445412114c20de0b837a0dfa33d6b82825fff44c9a70ea54ce47f07df698e6b03323b53079364a5fc3e9dd034392bdde86dccdda94321c5e44060489336cb65bf3989c36f7282c2f5d2b882c171e74',
 'key'    : '95d5c005503e510d8cd0aa072c4a4d066eabc52d11653df47fbf63ab198bcc26',
 'tag'    : 'f248312e578d9d58f8b7bb4d19105431'},
{'input_len': '208',
 'input'    : '248ac31085b6c2adaaa38259a0d7192c5c35d1bb4ef39ad94c38d1c82479e2dd2159a077024b0589bc8a20101b506f0a1ad0bbab76e83a83f1b94be6beae74e874cab692c5963a75436b776121ec9f62399a3e66b2d22707dae81933b6277f3c8516bcbe26dbbd86f373103d7cf4cad1888c952118fbfbd0d7b4bedc4ae4936aff91157e7aa47c54442ea78d6ac251d324a0fbe49d89cc3521b66d16e9c66a3709894e4eb0a4eedc4ae19468e66b81f271351b1d921ea551047abcc6b87a901fde7db79fa1818c11336dbc07244a40eb',
 'key'    : '000102030405060708090a0b0c0d0e0f00000000000000000000000000000000',
 'tag'    : 'bc939bc5281480fa99c6d68c258ec42f'},
{'input_len': '0',
 'input'    : '',
 'key'    : 'c8afaac331ee372cd6082de134943b174710130e9f6fea8d72293850a667d86c',
 'tag'    : '4710130e9f6fea8d72293850a667d86c'},
{'input_len': '12',
 'input'    : '48656c6c6f20776f726c6421',
 'key'    : '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
 'tag'    : 'a6f745008f81c916a20dcc74eef2b2f0'},
{'input_len': '32',
 'input'    : '0000000000000000000000000000000000000000000000000000000000000000',
 'key'    : '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
 'tag'    : '49ec78090e481ec6c26b33b91ccc0307'},
{'input_len': '128',
 'input'    : '89dab80b7717c1db5db437860a3f70218e93e1b8f461fb677f16f35f6f87e2a91c99bc3a47ace47640cc95c345be5ecca5a3523c35cc01893af0b64a620334270372ec12482d1b1e363561698a578b359803495bb4e2ef1930b17a5190b580f141300df30adbeca28f6427a8bc1a999fd51c554a017d095d8c3e3127daf9f595',
 'key'    : '2d773be37adb1e4d683bf0075e79c4ee037918535a7f99ccb7040fb5f5f43aea',
 'tag'    : 'c85d15ed44c378d6b00e23064c7bcd51'},
{'input_len': '528',
 'input'    : '000000000000000b170303020000000006db1f1f368d696a810a349c0c714c9a5e7850c2407d721acded95e018d7a85266a6e1289cdb4aeb18da5ac8a2b0026d24a59ad485227f3eaedbb2e7e35e1c66cd60f9abf716dcc9ac42682dd7dab287a7024c4eefc321cc0574e16793e37cec03c5bda42b54c114a80b57af26416c7be742005e20855c73e21dc8e2edc9d435cb6f6059280011c270b71570051c1c9b3052126620bc1e2730fa066c7a509d53c60e5ae1b40aa6e39e49669228c90eecb4a50db32a50bc49e90b4f4b359a1dfd11749cd3867fcf2fb7bb6cd4738f6a4ad6f7ca5058f7618845af9f020f6c3b967b8f4cd4a91e2813b507ae66f2d35c18284f7292186062e10fd5510d18775351ef334e7634ab4743f5b68f49adcab384d3fd75f7390f4006ef2a295c8c7a076ad54546cd25d2107fbe1436c840924aaebe5b370893cd63d1325b8616fc4810886bc152c53221b6df373119393255ee72bcaa880174f1717f9184fa91646f17a24ac55d16bfddca9581a92eda479201f0edbf633600d6066d1ab36d5d2415d71351bbcd608a25108d25641992c1f26c531cf9f90203bc4cc19f5927d834b0a47116d3884bbb164b8ec883d1ac832e56b3918a98601a08d171881541d594db399c6ae6151221745aec814c45b0b05b565436fd6f137aa10a0c0b643761dbd6f9a9dcb99b1a6e690854ce0769cde39761d82fcdec15f0d92d7d8e94ade8eb83fbe0',
 'key'    : '99e5822dd4173c995e3dae0ddefb97743fde3b080134b39f76e9bf8d0e88d546',
 'tag'    : '2637408fe13086ea73f971e3425e2820'},
{'input_len': '257',
 'input'    : 'cccccccccccccccccccccccccccccccccccccccccccccccccc80ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccceccccccccccccccccccccccccccccccccccccc5cccccccccccccccccccccccccccccccccccccccccce3ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccaccccccccccccccccccccce6cccccccccc000000afccccccccccccccccccfffffff5000000000000000000000000000000000000000000000000000000ffffffe70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000719205a8521dfc',
 'key'    : '7f1b02640000000000000000000000000000000000000000cccccccccccccccc',
 'tag'    : '8559b876eceed66eb37798c0457baff9'},
{'input_len': '39',
 'input'    : 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000800264',
 'key'    : 'e00016000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'tag'    : '00bd1258978e205444c9aaaa82006fed'},
{'input_len': '2',
 'input'    : '02fc',
 'key'    : '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
 'tag'    : '06120c0c0c0c0c0c0c0c0c0c0c0c0c0c'},
{'input_len': '415',
 'input'    : '7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7a7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b5c7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b6e7b007b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7a7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b5c7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b6e7b001300000000b300000000000000000000000000000000000000000000f20000000000000000000000000000000000002000efff0009000000000000000000000000100000000009000000640000000000000000000000001300000000b300000000000000000000000000000000000000000000f20000000000000000000000000000000000002000efff00090000000000000000007a000010000000000900000064000000000000000000000000000000000000000000000000fc',
 'key'    : '00ff000000000000000000000000000000000000001e00000000000000007b7b',
 'tag'    : '33205bbf9e9f8f7212ab9e2ab9b7e4a5'},
{'input_len': '118',
 'input'    : '77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777ffffffe9e9acacacacacacacacacacac0000acacec0100acacac2caca2acacacacacacacacacacac64f2',
 'key'    : '0000007f0000007f01000020000000000000cf77777777777777777777777777',
 'tag'    : '02ee7c8c546ddeb1a467e4c3981158b9'},
{'input_len': '131',
 'input'    : '8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5',
 'key'    : 'eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880',
 'tag'    : 'f3ffc7703f9400e52a7dfb4b3d3305d9'},
{'input_len': '16',
 'input'    : 'ffffffffffffffffffffffffffffffff',
 'key'    : '0200000000000000000000000000000000000000000000000000000000000000',
 'tag'    : '03000000000000000000000000000000'},
{'input_len': '16',
 'input'    : '02000000000000000000000000000000',
 'key'    : '02000000000000000000000000000000ffffffffffffffffffffffffffffffff',
 'tag'    : '03000000000000000000000000000000'},
{'input_len': '48',
 'input'    : 'fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000',
 'key'    : '0100000000000000000000000000000000000000000000000000000000000000',
 'tag'    : '05000000000000000000000000000000'},
{'input_len': '48',
 'input'    : 'fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101',
 'key'    : '0100000000000000000000000000000000000000000000000000000000000000',
 'tag'    : '00000000000000000000000000000000'},
{'input_len': '16',
 'input'    : 'fdffffffffffffffffffffffffffffff',
 'key'    : '0200000000000000000000000000000000000000000000000000000000000000',
 'tag'    : 'faffffffffffffffffffffffffffffff'},
{'input_len': '64',
 'input'    : 'e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000',
 'key'    : '0100000000000000040000000000000000000000000000000000000000000000',
 'tag'    : '14000000000000005500000000000000'},
{'input_len': '48',
 'input'    : 'e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000',
 'key'    : '0100000000000000040000000000000000000000000000000000000000000000',
 'tag'    : '13000000000000000000000000000000'}])
