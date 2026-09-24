# Third-party dependencies

Application code is MIT. Dependencies retain their own licenses; this is not a blanket relicensing of the distribution.

This project imports unmodified Python packages dynamically. `python-telegram-bot` is LGPL-3.0-only: users must retain notices, be able to replace/relink the library and debug modified combinations, and receive corresponding library source when distributing a binary bundle as required by that license. Do not impose restrictions on those rights. Certifi includes MPL-2.0 licensed certificate data. Cryptography binary wheels may contain additional bundled components and notices.

This release distributes application source and dependency references, **not prebuilt wheels or a prebuilt container**. Building an image for your own use is distinct from redistributing it. Before redistributing a built image, include the exact corresponding sources/notices for bundled copyleft components and audit the base operating system; the Python inventory alone is not a complete image compliance review.

The original wheel license/notice texts are retained under `third_party/licenses/`. Sources for each exact version are linked below. PyPI release metadata was checked on 2026-09-24; it reported no listed vulnerabilities for these 27 pinned versions. This is not a guarantee of vulnerability absence or an OS security audit.

| Package | Version | License | Source |
|---|---|---|---|
| annotated-doc | 0.0.5 | MIT | [exact source](https://files.pythonhosted.org/packages/5a/8e/38aa427ed5402449e226975b649c5dc73ccadfefeb95e6aecb8f8ea4b6b6/annotated_doc-0.0.5.tar.gz) |
| annotated-types | 0.8.0 | MIT | [exact source](https://files.pythonhosted.org/packages/5f/56/a8120250d128bed162cd73c76d45f6ef9991f3e068f62a8ee060afa3104a/annotated_types-0.8.0.tar.gz) |
| anyio | 4.15.1 | MIT | [exact source](https://files.pythonhosted.org/packages/a9/d2/f4d173e22df740bc37b1db102b386ba719b66e95b0f0d751f556b387e6d2/anyio-4.15.1.tar.gz) |
| APScheduler | 3.11.3 | MIT | [exact source](https://files.pythonhosted.org/packages/8c/6b/eeff360196bb20b312c9e762a820fd1b2c6d809466c755ef57863478e454/apscheduler-3.11.3.tar.gz) |
| argon2-cffi | 25.1.0 | MIT | [exact source](https://files.pythonhosted.org/packages/0e/89/ce5af8a7d472a67cc819d5d998aa8c82c5d860608c4db9f46f1162d7dab9/argon2_cffi-25.1.0.tar.gz) |
| argon2-cffi-bindings | 26.1.0 | MIT | [exact source](https://files.pythonhosted.org/packages/0b/43/bb8b6e8708d49a5ab36781333af092d9f483b198a2710d01281204640055/argon2_cffi_bindings-26.1.0.tar.gz) |
| certifi | 2026.7.22 | MPL-2.0 | [exact source](https://files.pythonhosted.org/packages/a3/c2/24167ea9858356b47a87a50d39908bfdb72ceeefe0041586e704e5376b3a/certifi-2026.7.22.tar.gz) |
| cffi | 2.1.1 | MIT-0 | [exact source](https://files.pythonhosted.org/packages/9e/ef/008a1939e372c06329a3fce4279c02f328488f3526744906eeec3da7ad5f/cffi-2.1.1.tar.gz) |
| click | 8.5.0 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/c7/0e/7fa0ef50764b67090eca4114772a2abf8b6148198475e54c660b97caeee6/click-8.5.0.tar.gz) |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/bb/ad/5d6702db60b1e40b41ef513b6967ff5848f307d50f8449baf1634f5908f1/cryptography-50.0.1.tar.gz) |
| fastapi | 0.141.1 | MIT | [exact source](https://files.pythonhosted.org/packages/8a/02/91e3416a8fdd715abb903a952a6bec7cdd8d14eed55d415fc8595524c319/fastapi-0.141.1.tar.gz) |
| h11 | 0.16.0 | MIT | [exact source](https://files.pythonhosted.org/packages/01/ee/02a2c011bdab74c6fb3c75474d40b3052059d95df7e73351460c8588d963/h11-0.16.0.tar.gz) |
| httpcore | 1.0.9 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/06/94/82699a10bca87a5556c9c59b5963f2d039dbd239f25bc2a63907a05a14cb/httpcore-1.0.9.tar.gz) |
| httpx | 0.28.1 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz) |
| idna | 3.19 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/5f/f7/abb373e5757eaec4b922b92f97ec8d6d7e057cf06778247604fbc4e7c3f3/idna-3.19.tar.gz) |
| Jinja2 | 3.1.6 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/df/bf/f7da0350254c0ed7c72f3e33cef02e048281fec7ecec5f032d4aac52226b/jinja2-3.1.6.tar.gz) |
| MarkupSafe | 3.0.3 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/7e/99/7690b6d4034fffd95959cbe0c02de8deb3098cc577c67bb6a24fe5d7caa7/markupsafe-3.0.3.tar.gz) |
| pycparser | 3.0 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/1b/7d/92392ff7815c21062bea51aa7b87d45576f649f16458d78b7cf94b9ab2e6/pycparser-3.0.tar.gz) |
| pydantic | 2.13.5 | MIT | [exact source](https://files.pythonhosted.org/packages/53/ef/fc4f868f4e2cee79f863883abffceff107875f569b848507319842d2a681/pydantic-2.13.5.tar.gz) |
| pydantic_core | 2.46.5 | MIT | [exact source](https://files.pythonhosted.org/packages/af/f9/8a06bea35ef8daf588f707784c973a7046e0034c8d8cfb08828eeffb8b75/pydantic_core-2.46.5.tar.gz) |
| python-multipart | 0.0.32 | Apache-2.0 | [exact source](https://files.pythonhosted.org/packages/5b/42/55c32bb9b12693c092ad250a0e82edb5b31ddeda6eb772de5f308b3804ad/python_multipart-0.0.32.tar.gz) |
| python-telegram-bot | 22.8 | LGPL-3.0-only | [exact source](https://files.pythonhosted.org/packages/ba/77/153517bb1ac1bba670c6fb1dbf09e1fd0730494b1705934e715391413a0d/python_telegram_bot-22.8.tar.gz) |
| starlette | 1.6.0 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/b5/b4/205b0d5241d934e8add0c38aa924c4f9fb7330834ff11e5444db964ec3f9/starlette-1.6.0.tar.gz) |
| typing-inspection | 0.4.4 | MIT | [exact source](https://files.pythonhosted.org/packages/a3/26/b09b8010994eccc3c09092e6b34058f36a460eea2d4c3e8b910c695975a0/typing_inspection-0.4.4.tar.gz) |
| typing_extensions | 4.16.0 | PSF-2.0 | [exact source](https://files.pythonhosted.org/packages/f6/cc/6253133b5bb138fc3306cebfbda2c520f545d36b5be2c7255cc528bb45d6/typing_extensions-4.16.0.tar.gz) |
| tzlocal | 5.4.4 | MIT | [exact source](https://files.pythonhosted.org/packages/81/5b/879b2f932adfa7a053c360d50bc896c977fa6426109185f7c12ebdd0cb9d/tzlocal-5.4.4.tar.gz) |
| uvicorn | 0.52.4 | BSD-3-Clause | [exact source](https://files.pythonhosted.org/packages/f2/0f/3f86e61397dd33bf2ccf28188c40db6a740658aeebbbf6e7dbc101a1f487/uvicorn-0.52.4.tar.gz) |
