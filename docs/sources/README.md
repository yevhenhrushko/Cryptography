# Источники исследования RSA

Скачаны оригинальные материалы с сайтов авторов, издателей и организаций.
Содержимое документов не изменялось. Оригинальные URL указаны в таблице ниже.
PDF проверены через `pdfinfo` и извлечение первой страницы.

| Материал | Локальная копия | Оригинал | Использование |
|---|---|---|---|
| Dan Boneh, *Twenty Years of Attacks on the RSA Cryptosystem* | [PDF, 16 страниц](boneh-rsa-survey.pdf) | [Stanford](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf) | Основной обзор: Винер, малые экспоненты, Хастад, Franklin–Reiter, ограничения атак |
| Nadia Heninger et al., *Mining Your Ps and Qs*, USENIX Security 2012 | [PDF, 16 страниц](mining-your-ps-and-qs-2012.pdf) | [USENIX](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final228.pdf) | Реальный случай восстановления ключей с общими простыми множителями |
| *Handbook of Applied Cryptography*, глава 3, Number-Theoretic Reference Problems | [PDF, 47 страниц](handbook-applied-cryptography-chapter-3.pdf) | [University of Waterloo](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) | Поллард p−1, алгоритм 3.14; учебная реализация проверяет НОД после каждого простого |
| *Handbook of Applied Cryptography*, глава 8, Public-Key Encryption | [PDF, 38 страниц](handbook-applied-cryptography-chapter-8.pdf) | [University of Waterloo](https://cacr.uwaterloo.ca/hac/about/chap8.pdf) | Справочник по RSA; общий модуль, раздел 8.2.2(vi) |
| RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2* | [Официальный текст](rfc8017.txt) | [RFC Editor](https://www.rfc-editor.org/rfc/rfc8017.txt) | RSAES-OAEP и различие между примитивом RSA и схемой шифрования |
| NIST SP 800-57 Part 1 Revision 5, *Recommendation for Key Management* | [PDF, 171 страница](nist-sp800-57-part1-rev5.pdf) | [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf) | Дополнительная сверка таблиц размера ключей и уровней стойкости; не источник оценки времени Ферма |

Статьи 1990-х и 2012 года используются как исторические и математические источники.
Указанные в старых статьях размеры ключей не следует воспринимать как современные рекомендации.
Сохранён именно документ NIST Revision 5, просмотренный при исследовании; это не утверждение,
что он является последней доступной редакцией на момент будущего чтения.

Формула времени в лабораторной работе — экстраполяция измеренного перебора Ферма, а не цитата из
этих документов и не оценка GNFS. Полный текст RFC сохранён в исходном текстовом формате;
для остальных пяти материалов сохранены исходные PDF.
