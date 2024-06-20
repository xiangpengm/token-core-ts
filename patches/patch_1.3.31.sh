mkdir -p patches
curl 'https://raw.githubusercontent.com/xiangpengm/token-core-ts/main/patches/scrypt-ts%2B1.3.31.patch' > 'patches/scrypt-ts+1.3.31.patch' 2>/dev/null
curl 'https://raw.githubusercontent.com/xiangpengm/token-core-ts/main/patches/scryptlib%2B2.1.41.patch' > 'patches/scryptlib+2.1.41.patch' 2>/dev/null
npm i scrypt-ts@1.3.31 scryptlib@2.1.41
patch-package
cd node_modules/scryptlib &&  npm run postinstall && cd ../../
rm -rf patches