# Security Policy

WebGuard ditujukan untuk pengujian keamanan yang telah mendapat izin.

## Scope penggunaan

Pengguna bertanggung jawab memastikan:
- target dimiliki sendiri atau izin pengujian diberikan secara eksplisit;
- host tambahan yang dimasukkan melalui `--scope-host` benar-benar termasuk scope;
- rate dan jumlah halaman sesuai batas yang disepakati;
- hasil temuan diverifikasi sebelum dilaporkan.

## Batas scanner

WebGuard 1.0 tidak melakukan:
- brute force kredensial;
- exploit SQL injection;
- exploit XSS;
- SSRF;
- command execution;
- upload file;
- penghapusan/perubahan data;
- bypass autentikasi;
- pengambilan data sensitif sebagai proof.

## Pelaporan hasil

Jika target menyediakan `security.txt`, ikuti kontak dan policy yang ditemukan. Jangan mempublikasikan detail kerentanan sebelum pemilik sistem memiliki kesempatan yang wajar untuk memperbaikinya.
