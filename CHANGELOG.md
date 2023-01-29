# Changelog

## [1.1.0](https://github.com/cxiao/hashdb_bn/compare/v1.0.0...v1.1.0) (2023-01-29)


### Features

* Allow negative token values in Hash Lookup ([c4114de](https://github.com/cxiao/hashdb_bn/commit/c4114de9fe32b45558840f8cc3ee645a7e8cfa5d))
* In Multiple Hash Lookup, still add successfully resolved hashes even if one request fails ([60a80ae](https://github.com/cxiao/hashdb_bn/commit/60a80aec0ccbbbfc81df3435a11aa6b257771cbc))


### Bug Fixes

* Fix error message formatting when selected text is invalid ([b63334f](https://github.com/cxiao/hashdb_bn/commit/b63334fde24e8474b6046620f72dc63a956e0824))

## 1.0.0 (2023-01-23)

This is the initial release to the Binary Ninja plugin manager.

### Features

* Add context menu entries for Hash Lookup, Hunt actions ([f958b5f](https://github.com/cxiao/hashdb_bn/commit/f958b5f942fe0051ea72e05f3a8eb417d8a505c4))
* Allow selection to be used for single-hash lookup and hunt tasks ([f3b6f61](https://github.com/cxiao/hashdb_bn/commit/f3b6f61fd759cfd39e078a0b0bf1373ceddcdc7e))
* Append algorithm name to enum when creating enums ([d040851](https://github.com/cxiao/hashdb_bn/commit/d040851ce8e58f7388f1977aaf95b71147976e62))
* Basic creation of enum and enum members on Hash Lookup action ([90a1140](https://github.com/cxiao/hashdb_bn/commit/90a1140a47de20be7288adf6ee0d72101a3bb049))
* Improve logging and user feedback when looking up hashes ([4e36040](https://github.com/cxiao/hashdb_bn/commit/4e36040f5331fa10e086cf2d59d08a7e0462fe5c))
* Make dialog box messages consistent ([de0b0ac](https://github.com/cxiao/hashdb_bn/commit/de0b0ac0ba2bcb02a5f01b2a549370e34ccaf3d3))
* Make multiple hash requests use asyncio ([e35d6bd](https://github.com/cxiao/hashdb_bn/commit/e35d6bdf0a157a1d2a0b463ddb468df3cc2eb8fe))
* Move hash lookup logic to background task ([b114f1e](https://github.com/cxiao/hashdb_bn/commit/b114f1ebd2bd7360e15580b62b22ab42584b052b))
* Move IAT Scan action to background task ([1b6e4b6](https://github.com/cxiao/hashdb_bn/commit/1b6e4b6e16d96f96ac5b280c93fc83dc73b6a200))
* Remove XOR key feature ([009488e](https://github.com/cxiao/hashdb_bn/commit/009488e75f0ee35efae92d9d8fa361461d960455))
* Show hash value when presenting user with hash collision selection box ([a4baca6](https://github.com/cxiao/hashdb_bn/commit/a4baca63a993a605dc5769d46700ac230028132f))
* Slightly improve appearance of hunt results window ([0c03c3b](https://github.com/cxiao/hashdb_bn/commit/0c03c3b0c4f45c8082fd962d8fb009f8d63d5fe2))
* Support 64-bit hash algorithms ([5bf7479](https://github.com/cxiao/hashdb_bn/commit/5bf7479bc4ccccf35ec0dc555ab59607efcd882c))
* Update "Change Hash Algorithm" to "Select Hash Algorithm" ([d775b37](https://github.com/cxiao/hashdb_bn/commit/d775b3756dba06bcf51d4934cb9fbae54e3809de))
* Use background task for hunt_algorithm command ([c889796](https://github.com/cxiao/hashdb_bn/commit/c889796580bbbc0573b244da7c5e71039a7c2230))


### Bug Fixes

* Always add looked up hash, even when user does not add the entire module ([e7ad9f2](https://github.com/cxiao/hashdb_bn/commit/e7ad9f207b748075ba94dec737a9b7559245e11a))
* Broken interaction for importing function hashes ([01c6cc4](https://github.com/cxiao/hashdb_bn/commit/01c6cc4d0e0bd64f266933f0ffb1a9f9f5baaaf0))
* Explicitly ensure analysis is updated after enum definition updates ([1df057d](https://github.com/cxiao/hashdb_bn/commit/1df057d9694c9a1a1f27e4d82c6d2a0ef45cf94c))
* Explicitly order context menu items ([f7020aa](https://github.com/cxiao/hashdb_bn/commit/f7020aa9b495d8c689b5343096807bbbb8461b2a))
* Fixup remaining empty settings checks ([98e3de9](https://github.com/cxiao/hashdb_bn/commit/98e3de99291736369b4401cc9e76b5483052a6ff))
* Handle potential None module name ([8ae78d4](https://github.com/cxiao/hashdb_bn/commit/8ae78d4b55b978bfd52c6e8ec61ffbfb65d32cd1))
* Move plugin menu to Plugins category ([e268bd5](https://github.com/cxiao/hashdb_bn/commit/e268bd57b7a4e612ba239d8e937b69d61538b5ff))
* Prompt user when performing hash lookup with no algorithm selected ([c15bc46](https://github.com/cxiao/hashdb_bn/commit/c15bc4682ba240e3c4723483886cc23cbf8b9001))
* Properly handle case where no hash collision was chosen ([6f3e809](https://github.com/cxiao/hashdb_bn/commit/6f3e8096c2b3adcc84ca8bf92ae0d7c6dfeb211e))
* Remove duplicate xor operation in hash_lookup, api.get_strings_from_hash ([1dec94a](https://github.com/cxiao/hashdb_bn/commit/1dec94a981f35d1c48ab20c8cdedc27735c611de))
* Remove Multiple Hash Lookup from global menu ([81fd4ef](https://github.com/cxiao/hashdb_bn/commit/81fd4efc716f8a19a65a4195beebf3a7bc5d7fb1))
* Remove use of typing.Self (only available in Python &gt;= 3.11) ([6e26058](https://github.com/cxiao/hashdb_bn/commit/6e26058384c173a253f13a8a8e4417d0ce43fa83))
* Use timeouts for API requests ([e48a253](https://github.com/cxiao/hashdb_bn/commit/e48a2534781a1d387950b833c0e551caa87d4d59))
