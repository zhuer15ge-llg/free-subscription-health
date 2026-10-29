// User-reported unreachable nodes, 2026-10-30. No passwords or subscription URIs.
// Match exact endpoints across publishers; no source-wide or subnet bans.
export const BLOCKED_NODE_IDS = Object.freeze([
  "free-0263f0cbbbe50e81",
  "free-03566fd5ffddf017",
  "free-042332c69b63bb54",
  "free-060bbc1eb11716f0",
  "free-0657f993aedeb189",
  "free-06bf47855d206687",
  "free-0751c8c6654281a0",
  "free-07b7813e5d635724",
  "free-07c6f79d1ded1dc9",
  "free-083b30e227f6de46",
  "free-086567b6cce390ce",
  "free-08cd6f993d199913",
  "free-0a5e2c527087e818",
  "free-0a69acb8096fd088",
  "free-0c2ed9807ace1d24",
  "free-0d4f1532ae03842c",
  "free-0e2f0e6d0b85e58d",
  "free-0e3daa8c10529bb0",
  "free-0f92365365ad24b9",
  "free-0fe0296fed9a0409",
  "free-112b6e5eb15258cc",
  "free-1217ae5ee4df1e5a",
  "free-12da9c4b1a1437ef",
  "free-1302c9251d92dc77",
  "free-16ea0145c5b19273",
  "free-17310a873eacdbc1",
  "free-176009ae71fe0938",
  "free-17d2d1de55f5de5e",
  "free-17dcf9db9d11cdb9",
  "free-182c2df8a299c9d2",
  "free-182e2586e31c85c0",
  "free-185261735dd0b967",
  "free-18d0600128bc4977",
  "free-1b320f38816318d4",
  "free-1c6c31180b09bde4",
  "free-1c8a6a38ab05acb2",
  "free-1ca5b57a6d8cbc42",
  "free-1fdc00a3a43f4225",
  "free-1fdeae35dd0bf3fb",
  "free-212dc6d9f3ece515",
  "free-22d3644e20a2bae6",
  "free-230c7a25683992ff",
  "free-2591a423fec07c9b",
  "free-25e346411b9a9097",
  "free-2808b53b4b8316af",
  "free-28c78d772caccbd9",
  "free-295250b2e39c6d4a",
  "free-2979c3412adfa0cd",
  "free-29fc0bdc99168806",
  "free-2c5584c0d5daf328",
  "free-2ec407702d2efe6a",
  "free-2ee3ecfb910db7dd",
  "free-2fdc93850ec4d9b5",
  "free-30acbafe52df049e",
  "free-312b04edfbba7cfd",
  "free-32a2a008dcb0ec68",
  "free-32b2372383a1125b",
  "free-3322e882b718f362",
  "free-33a2348bfeaa5709",
  "free-33f7436ff02ac173",
  "free-3401d1696c484723",
  "free-34e9fc24c6568c28",
  "free-34ef6a86ad951b64",
  "free-35318a165ced51de",
  "free-35a96924c1e588ec",
  "free-360fba732c458b61",
  "free-37325895b2479f21",
  "free-38132f02202c5c70",
  "free-392e90f6d853cf00",
  "free-3a8742e0171dd784",
  "free-3ada5c8971adecd1",
  "free-3be0cc5eb018b878",
  "free-3c72f1dd5695a219",
  "free-3c897a4b1dca2cab",
  "free-3d57bf6c349a7eea",
  "free-3daff2adb8531dfd",
  "free-3ddebae61e33974e",
  "free-3f0148f282532284",
  "free-3f482040b1917f9c",
  "free-401eaf1426f2ebda",
  "free-40338a10e75202b0",
  "free-40bdb3357d893157",
  "free-41107f27c57eac71",
  "free-41ca058a696ce8e4",
  "free-444b068384f82df3",
  "free-459f72a7e1cbb913",
  "free-45a0af95946d77f5",
  "free-46ded1f716012617",
  "free-46eda3b870b7911e",
  "free-470a2a70414ff9fa",
  "free-48ad401d67c0077f",
  "free-4bfc7c24404672c2",
  "free-4c5bd18af3878d80",
  "free-4dbc278351bd3c09",
  "free-4dd2b069d3c9ec91",
  "free-4dd629332f639a35",
  "free-4f02bac5f4e7199f",
  "free-4f3fef472056a385",
  "free-4fdc557a85bf2a40",
  "free-4ff02b66073007fc",
  "free-50ea73a899be8002",
  "free-5254af03b902f699",
  "free-528448fcf4b72bc2",
  "free-531713f332ea4dd1",
  "free-553ae1df990c70f1",
  "free-557458da4d329fe8",
  "free-561094ebbe63bdf9",
  "free-5754c91924f9a01b",
  "free-59e514d570e7177d",
  "free-5a38a9a323e998d1",
  "free-5a6328d19eaadb21",
  "free-5bcc3e2b8f773057",
  "free-5bfab66d2e86afef",
  "free-5c1373ad67e9919d",
  "free-5d87161166b25ce7",
  "free-5db00907a5019169",
  "free-5ed7edf48bd9e7f6",
  "free-601a7a60652f3340",
  "free-6025a60eb6b4874e",
  "free-610e04fd7a5eee45",
  "free-628c7f438521dd17",
  "free-63150b0f4bd4c14d",
  "free-635a0458a0235680",
  "free-636dc50ac9c06f0c",
  "free-6565ec50438a3766",
  "free-660a1f29ac9e7b59",
  "free-66f2e4ded894a560",
  "free-677b62dd4277fc31",
  "free-67b15af3b1fe2f93",
  "free-68609b1fe17bf31b",
  "free-68a6ce2404eb9dfe",
  "free-699cd74f5b680ef7",
  "free-6a0c5d7d777a1eb7",
  "free-6cbe3bd905f720d7",
  "free-6cfa13a6d5d1de5e",
  "free-6d2205f132ad2035",
  "free-6de302c8c3e54f06",
  "free-6e2c72785d776812",
  "free-6e8ecada5a2987aa",
  "free-6eb5ad9c1b584aa4",
  "free-70ac0facc31adaf2",
  "free-7138c3b1b7de3a7d",
  "free-71534e9b4578206d",
  "free-7163737af5603f56",
  "free-71cac2add184294d",
  "free-72bbc8fef4577ed0",
  "free-73d5449f0d08b5cb",
  "free-74146b795d040491",
  "free-74eef9068db7b338",
  "free-78371db2425a6288",
  "free-78662a8e9beda9d8",
  "free-7af3bec833117892",
  "free-7d1915d112e057b9",
  "free-7d5c53a8c74c1048",
  "free-7e06b8228870358e",
  "free-7fa95c76fe1107ea",
  "free-7faffc6e783b1f78",
  "free-7fdd76ec606ef8ce",
  "free-81e1477b96189d6f",
  "free-81e4e99fb59f969d",
  "free-831d1e946f8e0b4a",
  "free-841f7ed63ad6ffc4",
  "free-84bf75d4463e858e",
  "free-85ccb73afa565132",
  "free-881d35665da65068",
  "free-883bd7dd8e1d0a3d",
  "free-88dc5026b9d26894",
  "free-89bbdc95b2d5b1ff",
  "free-8b915b471bd5f0cd",
  "free-8c5eba7e93197fb2",
  "free-8c7e81ce31516f76",
  "free-8fd073d56a91fd29",
  "free-8ffd91012397d4ff",
  "free-91ed085da127efab",
  "free-92fb272a28cf7038",
  "free-938e734f48fc91ef",
  "free-951718cf470ed4d3",
  "free-9554600d5a63e107",
  "free-9584499c4b6293b6",
  "free-969ef3f5dde61a19",
  "free-96f2dd73b5cb907b",
  "free-994d606ee090b8dc",
  "free-9b95032e0fd31be0",
  "free-9bf7688d8b05d9fb",
  "free-9c01eba2b03ec19e",
  "free-9c1b3b3bdd255447",
  "free-9c26728d9bac4a9d",
  "free-9f19c0c4fcbfd7de",
  "free-9f222bf798e325e1",
  "free-9feb2994ab8d56f2",
  "free-a0120516470fea78",
  "free-a0c787034c5b982d",
  "free-a26ac8292016d1b5",
  "free-a28a2b61361290cf",
  "free-a4589de8e42e8a32",
  "free-a47880c5444dbfd5",
  "free-a50971ed5ac4cba5",
  "free-a6d0875599a10327",
  "free-a893aabfe65aaf33",
  "free-a89600ff669edec9",
  "free-a9927765b97f0b6d",
  "free-a9aae8d7d478de41",
  "free-a9acd185f4c25cc9",
  "free-ade9fb69ddacc8f9",
  "free-ae7639e611ed9c16",
  "free-af082266e534d1e8",
  "free-b13dc60557931507",
  "free-b15cb5510a560a49",
  "free-b18c9072ce911fee",
  "free-b1b8a09138c27449",
  "free-b3b09d0aec86f9bc",
  "free-b5b60be08b6ff2da",
  "free-b7baa201873a2c9b",
  "free-b7eb2793b6d8f5a5",
  "free-b8be4c5dc511d0b7",
  "free-ba238e5bf6b45511",
  "free-ba5746030c066153",
  "free-bba2a9e3a77df31f",
  "free-bbfa34aaee9fe3c2",
  "free-be2f71432c540f85",
  "free-bf4c9220f55865b4",
  "free-c064334d9d8e0da1",
  "free-c0a03955ae000663",
  "free-c0ac0686b773b2c4",
  "free-c0e28b28677bb41a",
  "free-c17562895aadcf41",
  "free-c1d34aa5f604e23b",
  "free-c4d731995616e593",
  "free-c4fd384fbe47dc8d",
  "free-c570aac1698c50b1",
  "free-c86218b3bf66d007",
  "free-c962e05f0f890267",
  "free-ca1ca629b40774a7",
  "free-cbb4805ac154af16",
  "free-cbe77e3f16f1cb31",
  "free-cc5a5bfbc50b5fdf",
  "free-ccc7d4d36974299b",
  "free-cd8881b70599a2f3",
  "free-d1573c01038519f9",
  "free-d25e9bc22946f48c",
  "free-d319d16767940bb7",
  "free-d38a20fdddc390ef",
  "free-d4fd9e1e14fe7ad6",
  "free-d59b810e7a129d2c",
  "free-d77f6aa991c29305",
  "free-d89656b456c4dca4",
  "free-d9c769f33ae811b5",
  "free-d9cf11726af3dd7c",
  "free-d9eb328ef7759ea8",
  "free-ddf19624f89d554c",
  "free-de29a25647171864",
  "free-dfd3bc664c06f0de",
  "free-e0b614b2d2f17220",
  "free-e1c06caba37eddc7",
  "free-e27b5737b110b01d",
  "free-e5b0e426791254c4",
  "free-e5d6a5bb9417f3b3",
  "free-e73d0b6c01484f6e",
  "free-e7412a36c0974f88",
  "free-e7e00440ae9004b4",
  "free-e83baae3354d8837",
  "free-eab576a48012c688",
  "free-f0c0680e4f96c2ee",
  "free-f27c6b5ebebb9328",
  "free-f3b0fa28e69c3240",
  "free-f445bdbeaea9e7ae",
  "free-f4c54eea4bd23514",
  "free-f58d34a2e15ffeca",
  "free-f66e7cb60a493f12",
  "free-f6c35b3a8e298978",
  "free-f6d5c6b937612147",
  "free-f746530cdd41b252",
  "free-f8ab50edb0938733",
  "free-f966a6175300d6bb",
  "free-fb274e87285d1811",
  "free-fbde993d7ffa4f37",
  "free-fc012b5904aa6d45",
  "free-fc2489b997845d49",
  "free-fc594aa3f3cada99",
  "free-fcfe671db1cae5b7",
  "free-fd8123a18198db2b",
  "free-fdc7183ea9f76f02",
  "free-fe16c96bfb774c95",
  "free-ff85d5a8663cf0d0",
  "free-ffa02404f8b46d60"
]);
export const BLOCKED_ENDPOINTS = Object.freeze([
  {
    "protocol": "hysteria2",
    "server": "119.236.249.101",
    "port": 443
  },
  {
    "protocol": "hysteria2",
    "server": "150-230-252-217.liao.kdns.fr",
    "port": 50160
  },
  {
    "protocol": "hysteria2",
    "server": "150.230.252.217",
    "port": 50160
  },
  {
    "protocol": "hysteria2",
    "server": "151.243.169.164",
    "port": 12824
  },
  {
    "protocol": "hysteria2",
    "server": "45.32.10.7",
    "port": 443
  },
  {
    "protocol": "hysteria2",
    "server": "vp3.yysyy.online",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "104.253.216.227",
    "port": 49917
  },
  {
    "protocol": "ss",
    "server": "13.124.223.116",
    "port": 8443
  },
  {
    "protocol": "ss",
    "server": "130.49.189.158",
    "port": 43558
  },
  {
    "protocol": "ss",
    "server": "132.243.175.144",
    "port": 8388
  },
  {
    "protocol": "ss",
    "server": "141.98.101.181",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "149.22.87.204",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "149.22.87.240",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "149.22.87.241",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "149.22.95.183",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "156.146.38.167",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "156.146.38.168",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "156.146.38.169",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "156.146.38.170",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "158.173.20.208",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "173.244.56.6",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "173.244.56.9",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "178.253.16.185",
    "port": 8388
  },
  {
    "protocol": "ss",
    "server": "178.83.185.156",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "185.164.175.81",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "185.176.204.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "185.176.206.9",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "185.215.132.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "185.215.132.9",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "185.226.172.8",
    "port": 8008
  },
  {
    "protocol": "ss",
    "server": "185.230.230.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "193.151.160.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "193.151.160.9",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "193.151.163.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "193.29.139.147",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.188",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.198",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.202",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.204",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.223",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.225",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "193.29.139.235",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "216.128.153.186",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "37.19.198.160",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "37.19.198.236",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "37.19.198.243",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "37.19.198.244",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "45.86.51.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "57.131.48.45",
    "port": 8388
  },
  {
    "protocol": "ss",
    "server": "82.110.60.9",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "82.38.31.10",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.11",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.149",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.149",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.155",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.156",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.157",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.159",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.16",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.162",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.169",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.17",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.170",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.174",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.174",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.175",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "82.38.31.175",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.176",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.179",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.180",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.181",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.184",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.187",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.191",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.192",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.193",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.199",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.200",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.201",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.202",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.203",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.204",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.210",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.212",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.214",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.219",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.26",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.34",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.35",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.39",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.42",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.47",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.48",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.49",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.62",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.66",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.69",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.82",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "82.38.31.9",
    "port": 8080
  },
  {
    "protocol": "ss",
    "server": "95.215.201.18",
    "port": 19999
  },
  {
    "protocol": "ss",
    "server": "ams1.rvpn.app",
    "port": 8388
  },
  {
    "protocol": "ss",
    "server": "pl134.vpnbook.com",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "pl140.vpnbook.com",
    "port": 443
  },
  {
    "protocol": "ss",
    "server": "sql.popmintxo.cc",
    "port": 43385
  },
  {
    "protocol": "trojan",
    "server": "149.28.130.108",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "155.103.71.142",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "170.101.101.19",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "191.96.94.226",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "2.27.109.179",
    "port": 45464
  },
  {
    "protocol": "trojan",
    "server": "216.106.186.32",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.147.152",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.147.74",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.155.176",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.155.23",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.155.54",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.156.212",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.156.42",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.156.49",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.156.65",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.152.156.81",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.238.104.154",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "216.238.80.100",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "45.63.30.142",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "45.87.41.18",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.112.121",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.112.31",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.114.114",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.114.126",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.114.132",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.114.166",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.118.166",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.118.244",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.122.7",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "66.163.122.81",
    "port": 443
  },
  {
    "protocol": "trojan",
    "server": "77.221.138.199",
    "port": 8443
  },
  {
    "protocol": "trojan",
    "server": "blog.findlocaljobnetworkandbuildcommunityconnections.com",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "104.253.216.227",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "107.189.7.176",
    "port": 32752
  },
  {
    "protocol": "vless",
    "server": "108.61.164.217",
    "port": 4443
  },
  {
    "protocol": "vless",
    "server": "109.248.170.119",
    "port": 13447
  },
  {
    "protocol": "vless",
    "server": "130.12.242.106",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "134.185.81.5",
    "port": 47881
  },
  {
    "protocol": "vless",
    "server": "137.74.16.237",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "138.124.70.41",
    "port": 14430
  },
  {
    "protocol": "vless",
    "server": "144.48.11.97",
    "port": 43000
  },
  {
    "protocol": "vless",
    "server": "146.19.143.218",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "148-253-210-191.sslip.io",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "15.204.97.195",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "15.204.97.206",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "15.204.97.214",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "151.245.106.49",
    "port": 2053
  },
  {
    "protocol": "vless",
    "server": "152.228.139.33",
    "port": 51671
  },
  {
    "protocol": "vless",
    "server": "152.69.226.63",
    "port": 25555
  },
  {
    "protocol": "vless",
    "server": "155.117.5.208",
    "port": 20001
  },
  {
    "protocol": "vless",
    "server": "156.224.79.61",
    "port": 9443
  },
  {
    "protocol": "vless",
    "server": "165.154.63.139",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "169.40.42.104",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "169.40.42.163",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "169.40.42.202",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "169.40.42.229",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "169.40.42.89",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "169.40.42.90",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "170.114.45.6",
    "port": 8080
  },
  {
    "protocol": "vless",
    "server": "170.114.46.6",
    "port": 8080
  },
  {
    "protocol": "vless",
    "server": "172.237.88.103",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "177.3.208.65",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "177.7.51.29",
    "port": 8443
  },
  {
    "protocol": "vless",
    "server": "178.172.227.124",
    "port": 14430
  },
  {
    "protocol": "vless",
    "server": "178.172.227.228",
    "port": 14430
  },
  {
    "protocol": "vless",
    "server": "178.236.16.98",
    "port": 35728
  },
  {
    "protocol": "vless",
    "server": "178.83.45.226",
    "port": 2052
  },
  {
    "protocol": "vless",
    "server": "178.83.45.226",
    "port": 8080
  },
  {
    "protocol": "vless",
    "server": "18.183.215.124",
    "port": 28573
  },
  {
    "protocol": "vless",
    "server": "191.44.108.31",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "193.163.203.170",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "193.238.154.78",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "195.123.208.32",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "195.123.213.28",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "195.123.221.36",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "195.123.235.183",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "208.84.100.209",
    "port": 8080
  },
  {
    "protocol": "vless",
    "server": "263651t.fi3.h1clayd.click",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "3.0.111.82",
    "port": 10574
  },
  {
    "protocol": "vless",
    "server": "3.0.111.82",
    "port": 12972
  },
  {
    "protocol": "vless",
    "server": "3.0.111.82",
    "port": 17623
  },
  {
    "protocol": "vless",
    "server": "3.114.220.22",
    "port": 10583
  },
  {
    "protocol": "vless",
    "server": "3.114.220.22",
    "port": 18007
  },
  {
    "protocol": "vless",
    "server": "3.114.220.22",
    "port": 19645
  },
  {
    "protocol": "vless",
    "server": "3.39.4.109",
    "port": 13672
  },
  {
    "protocol": "vless",
    "server": "3.39.4.109",
    "port": 18967
  },
  {
    "protocol": "vless",
    "server": "45.138.100.248",
    "port": 10443
  },
  {
    "protocol": "vless",
    "server": "45.138.100.248",
    "port": 14430
  },
  {
    "protocol": "vless",
    "server": "45.154.26.63",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "46.28.71.247",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "46.29.255.123",
    "port": 59539
  },
  {
    "protocol": "vless",
    "server": "5.178.109.174",
    "port": 14430
  },
  {
    "protocol": "vless",
    "server": "5.34.178.120",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "51.158.206.103",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.12",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.20",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.26",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.29",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.34",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.8",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.80",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.93",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.96",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.97",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.158.206.98",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "51.161.204.242",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "51.89.194.151",
    "port": 2053
  },
  {
    "protocol": "vless",
    "server": "54.169.200.246",
    "port": 41688
  },
  {
    "protocol": "vless",
    "server": "54.251.9.130",
    "port": 24146
  },
  {
    "protocol": "vless",
    "server": "62.105.220.106",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "62.210.91.2",
    "port": 23576
  },
  {
    "protocol": "vless",
    "server": "77.42.12.225",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "82.118.16.187",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "82.118.16.189",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "86.54.28.75",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "8fc752g.fi3.h1clayd.click",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "93.152.223.244",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "94.156.79.93",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "95.128.71.79",
    "port": 14430
  },
  {
    "protocol": "vless",
    "server": "a0688bt.us4.h1clayd.click",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "ai.smrtai.top",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "connect.hondamotor.site",
    "port": 10002
  },
  {
    "protocol": "vless",
    "server": "edge10.cyrionflare.com",
    "port": 2052
  },
  {
    "protocol": "vless",
    "server": "germany1.xorsand.eu",
    "port": 10105
  },
  {
    "protocol": "vless",
    "server": "in.smrtai.top",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "milo.networkforexir.site",
    "port": 8080
  },
  {
    "protocol": "vless",
    "server": "ph001.zestapp778.com",
    "port": 15656
  },
  {
    "protocol": "vless",
    "server": "ru1.radiolumens.uk",
    "port": 8445
  },
  {
    "protocol": "vless",
    "server": "sg2-8sb.6121999.dpdns.org",
    "port": 19825
  },
  {
    "protocol": "vless",
    "server": "sino.bestsellers1.site",
    "port": 2083
  },
  {
    "protocol": "vless",
    "server": "site.teslamotor.site",
    "port": 20001
  },
  {
    "protocol": "vless",
    "server": "staging.lastilhame.monster",
    "port": 443
  },
  {
    "protocol": "vless",
    "server": "support.zoom.us",
    "port": 8080
  },
  {
    "protocol": "vless",
    "server": "th001.zestapp778.com",
    "port": 22222
  },
  {
    "protocol": "vless",
    "server": "uk.2ul.top",
    "port": 443
  },
  {
    "protocol": "vmess",
    "server": "129.146.77.248",
    "port": 39495
  },
  {
    "protocol": "vmess",
    "server": "130.94.16.109",
    "port": 80
  },
  {
    "protocol": "vmess",
    "server": "132.145.80.230",
    "port": 80
  },
  {
    "protocol": "vmess",
    "server": "134.195.196.211",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "149.88.23.202",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "149.88.23.207",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "169.197.142.22",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "38.107.234.57",
    "port": 80
  },
  {
    "protocol": "vmess",
    "server": "38.91.107.49",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "3h-kazakhstan1.09vpn.com",
    "port": 80
  },
  {
    "protocol": "vmess",
    "server": "43.130.35.53",
    "port": 10087
  },
  {
    "protocol": "vmess",
    "server": "67.220.85.46",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "6jdvarazgu3qqr6q.v.3dns.vip",
    "port": 443
  },
  {
    "protocol": "vmess",
    "server": "8.210.24.181",
    "port": 443
  },
  {
    "protocol": "vmess",
    "server": "8.219.97.17",
    "port": 443
  },
  {
    "protocol": "vmess",
    "server": "84.17.41.2",
    "port": 18000
  },
  {
    "protocol": "vmess",
    "server": "vah4urdzl3jdx5r2.v.3dns.vip",
    "port": 443
  },
  {
    "protocol": "vmess",
    "server": "wjofhsqteueywxeq.v.3dns.vip",
    "port": 443
  },
  {
    "protocol": "vmess",
    "server": "ww11.levikogjgfdd.ir",
    "port": 18000
  }
].map(Object.freeze));

const ids = new Set(BLOCKED_NODE_IDS);
function endpointKey(protocol, server, port) {
  const host = String(server ?? '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const type = protocol === 'hy2' ? 'hysteria2' : protocol;
  return JSON.stringify([type, host, Number(port)]);
}
const endpoints = new Set(BLOCKED_ENDPOINTS.map(n => endpointKey(n.protocol, n.server, n.port)));
export function isBlockedNode(node) {
  if (!node) return false;
  if (ids.has(node.id)) return true;
  const protocol = node.protocol ?? node.proxy?.type ?? node.outbound?.type ?? node.type;
  const server = node.proxy?.server ?? node.outbound?.server ?? node.server ?? node.ip;
  const port = node.proxy?.port ?? node.outbound?.server_port ?? node.server_port ?? node.port;
  return endpoints.has(endpointKey(protocol, server, port));
}
