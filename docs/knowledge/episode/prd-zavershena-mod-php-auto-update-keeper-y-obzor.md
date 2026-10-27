---
type: episode
scope: project
title: 'PRD завершена: mod_php, auto-update keeper и обзор'
tags:
  - apache2
  - debian
  - deployment
  - automation
  - testing
refs:
  - project::project/php2shell-fixer
session_id: 61e04238-ee30-4191-964e-5e38057b17bf
outcome: success
files_touched:
  - CHANGELOG.md
  - README.md
  - scripts/audit.sh
  - scripts/autoupdate.sh
  - scripts/ensure.sh
  - scripts/fix.sh
  - scripts/lib/branch.sh
  - scripts/lib/hostfacts.sh
  - scripts/lib/logs.sh
  - scripts/lib/mitigation.sh
  - scripts/lib/p2s.sh
  - scripts/lib/pins.sh
  - scripts/next.sh
  - scripts/report.sh
  - scripts/run.sh
  - skills/php2shell/SKILL.md
  - tests/fixtures/hosts/web-l/active.txt
  - tests/fixtures/hosts/web-l/apachectl-S.txt
  - tests/fixtures/hosts/web-l/debs/php8.3-common=8.3.6-0ubuntu0.24.04.13/changelog.Debian
  - tests/fixtures/hosts/web-l/dpkg-query.txt
  - tests/fixtures/hosts/web-l/http.txt
  - tests/fixtures/hosts/web-l/madison/libapache2-mod-php8.3.txt
  - tests/fixtures/hosts/web-l/root/etc/apache2/apache2.conf
  - tests/fixtures/hosts/web-l/root/etc/apache2/mods-available/php8.3.conf
  - tests/fixtures/hosts/web-l/root/etc/apache2/mods-available/php8.3.load
  - tests/fixtures/hosts/web-l/root/etc/apache2/mods-enabled/php8.3.conf
  - tests/fixtures/hosts/web-l/root/etc/apache2/mods-enabled/php8.3.load
  - tests/fixtures/hosts/web-l/root/etc/apache2/sites-available/shop.conf
  - tests/fixtures/hosts/web-l/root/etc/apache2/sites-enabled/shop.conf
  - tests/fixtures/hosts/web-l/root/etc/os-release
  - tests/fixtures/hosts/web-l/root/etc/php/8.3/apache2/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-l/root/etc/php/8.3/cli/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-l/root/usr/share/doc/php8.3-common/changelog.Debian
  - tests/fixtures/hosts/web-l/started.txt
  - tests/fixtures/hosts/web-v/active.txt
  - tests/fixtures/hosts/web-v/dpkg-query.txt
  - tests/fixtures/hosts/web-v/root/etc/apache2/apache2.conf
  - tests/fixtures/hosts/web-v/root/etc/apache2/conf-enabled/uploads.conf
  - tests/fixtures/hosts/web-v/root/etc/apache2/mods-available/php7.4.load
  - tests/fixtures/hosts/web-v/root/etc/apache2/mods-available/php8.3.load
  - tests/fixtures/hosts/web-v/root/etc/apache2/mods-enabled/php8.3.load
  - tests/fixtures/hosts/web-v/root/etc/apache2/sites-available/old.conf
  - tests/fixtures/hosts/web-v/root/etc/apache2/sites-available/shop.conf
  - tests/fixtures/hosts/web-v/root/etc/apache2/sites-enabled/shop.conf
  - tests/fixtures/hosts/web-v/root/etc/os-release
  - tests/fixtures/hosts/web-v/root/etc/php/7.4/apache2/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-v/root/etc/php/8.3/apache2/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-v/root/etc/php/8.3/cli/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-v/root/usr/share/doc/php8.3-common/changelog.Debian
  - tests/fixtures/hosts/web-x/active.txt
  - tests/fixtures/hosts/web-x/apachectl-S.txt
  - tests/fixtures/hosts/web-x/debs/php8.3-common=8.3.6-0ubuntu0.24.04.13/changelog.Debian
  - tests/fixtures/hosts/web-x/dpkg-query.txt
  - tests/fixtures/hosts/web-x/http.txt
  - tests/fixtures/hosts/web-x/madison/php8.3-fpm.txt
  - tests/fixtures/hosts/web-x/root/etc/apache2/apache2.conf
  - tests/fixtures/hosts/web-x/root/etc/apache2/mods-available/php8.3.load
  - tests/fixtures/hosts/web-x/root/etc/apache2/mods-enabled/php8.3.load
  - tests/fixtures/hosts/web-x/root/etc/apache2/sites-available/shop.conf
  - tests/fixtures/hosts/web-x/root/etc/apache2/sites-enabled/shop.conf
  - tests/fixtures/hosts/web-x/root/etc/nginx/nginx.conf
  - tests/fixtures/hosts/web-x/root/etc/nginx/sites-enabled/api
  - tests/fixtures/hosts/web-x/root/etc/os-release
  - tests/fixtures/hosts/web-x/root/etc/php/8.3/apache2/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-x/root/etc/php/8.3/cli/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-x/root/etc/php/8.3/fpm/conf.d/10-opcache.ini
  - tests/fixtures/hosts/web-x/root/etc/php/8.3/fpm/pool.d/www.conf
  - tests/fixtures/hosts/web-x/root/usr/share/doc/php8.3-common/changelog.Debian
  - tests/fixtures/hosts/web-y/active.txt
  - tests/fixtures/hosts/web-y/apt-config.txt
  - tests/fixtures/hosts/web-y/dpkg-query.txt
  - tests/fixtures/hosts/web-y/madison/php8.3-common.txt
  - tests/fixtures/hosts/web-y/madison/php8.3-fpm.txt
  - tests/fixtures/hosts/web-y/madison/php8.4-common.txt
  - tests/fixtures/hosts/web-y/madison/php8.4-fpm.txt
  - tests/fixtures/hosts/web-y/root/etc/apt/sources.list.d/ondrej-ubuntu-php-noble.sources
  - tests/fixtures/hosts/web-y/root/etc/os-release
  - tests/fixtures/hosts/web-y/root/var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_noble_InRelease
  - tests/fixtures/logs/needs-autoupdate-audit-20261026T090000.000Z.log
  - tests/run.sh
ended_at: "2026-10-27T16:30:33Z"
status: active
git:
  repo_root: /home/alexturik/ALEXTURIK_DEV/CC_PLUGINS_BY_ALEXTURIK/php2shell-fixer
  branch: main
  parent_branch: ""
  base_sha: 806e283ac20cddf3a1b6020752738df9baef083b
  head_sha: 871d778bd458407f00f56ff28ee29838f03c9535
  commits_sha:
    - 517630f08e5f16fc6a0900f647a083a314528fed
    - e4fd56b4cae42e28bb05d46c4dfd2d97b66bb6ad
    - da3c10d91b4be9f84f4275d2ed3b998feff01b0d
    - 4922e35f64f792d3edc0913513c95b7dea2031f7
    - 362ea32ee67fb1d4925175463b05a28725fb8e0b
    - cae0c036b1e3c26f98de1be9fa6e10cd64551558
    - bb334984587aa808a136bec90284645cbf696315
    - fcc21caa19f28959ee1ac1bb7061222ef9cd3b31
    - 8a74957e7a609d534c51659c6050491cd9526c61
    - bb0b69bfbae6fb771c86b65bdd9478e173027a55
    - 895256fb6cf654a2cf32e4c40e2c3ad5e8454131
    - 5771a23b9f5ea31cbcf7715ec4b84062bf612270
    - f9129db9d540e8dbe845fa0ff2654132e9eb8acf
    - 0b115b98d8cd87ca7412651e1e514d39c09e2be9
    - 6a35999f506011d05355020e7e317504978ccb01
    - 9c96041cee35a8eb6e0ca8fd17f78c791bf509b5
    - 619da5c74aec1785da3b5074680a15b7b5e799ea
    - 7cd3d5bf633d9fbb5e765358fc1a0b4c4493dcd3
    - f32219b3c00d962e30e875b84d5a61fa65d0a40c
    - 74ce81ecc52b628b06b27803bb6947bb7351bacd
    - 58b4b9808e4dcb13c5a815540c0de541690e36c2
    - ef5cb094b024915d031485203686d2304ea3fa93
    - 831b314ac488e722b145dd2b9a93816233a15def
    - 3c7d1d4a26ea6216e65e10d5e1b458ca38fbbfda
    - e25bc5265264715cd4e5d1520dd09e931241b4b3
    - 9613f7844d3ccb7df37737e7748939fc9f9f4b4e
    - c84936361e0355009cbb75bcc5fcebde8a98c0dc
    - c2e44198f66e9200719a8c2735e0f25984458463
    - fe439899005df8011d44527c2c2533e751342297
    - a352e8c6b34b6163d22e893224fb2a097c987d14
    - 480e58e63024b43b43456cc7f2f4d423d0be70ec
    - 0c4e53b0ad9338b8a8b3b12c7f32175c6025a4f7
    - 352c52976b33396985aeefb000e8e2c48959354b
    - bd8d9e5206149299cfc71a1f593489b5f1267936
    - bb2f2dcbbb377aa90514ed796090129dd790536a
    - ed2cd8a9174213b91fda52748f0eb9bb437e6424
    - 1d026a96f8780188e00604b896e85eca4e002cbc
    - 4babf28b1ed01e6a3f395a25f4db877be03a8cee
    - de29f81b2309664837158c73029f2696fba55618
    - 6fcd007034f78bb95ff4187f2586067ad8383cf9
    - 871d778bd458407f00f56ff28ee29838f03c9535
  remote_url: https://github.com/turovskiy/php2shell-fixer.git
  base_sha_orphan: false
id: episode/prd-zavershena-mod-php-auto-update-keeper-y-obzor
created: "2026-10-27T16:30:34Z"
updated: "2026-10-27T16:30:34Z"
confidence: 0.58
review: unreviewed
tier: supporting
summary: '**Цель:** завершить PRD #1 (php2shell-fixer) путем реализации последних двух заблокированных тикетов (#9 mod_php и #10 auto-update keeper), провести полный обзор гілки і мержить в main.'
---

# PRD завершена: mod_php, auto-update keeper и обзор

## PRD #1 на финише: mod_php, auto-update keeper и обзор

**Цель:** завершить PRD #1 (php2shell-fixer) путем реализации последних двух заблокированных тикетов (#9 mod_php и #10 auto-update keeper), провести полный обзор гілки і мержить в main.

**Что произошло:**

Сессия охватила 4,5 часов структурированной работы: делегирование двум TDD-агентам, двухосевый обзор, ремонт 18 багов, мержи, и follow-up задачи.

1. **Реализация #9 (mod_php).** Первый субагент через TDD: аудит показывает Apache с mod_php отдельным SAPI `apache2`, проверка перезагрузки Apache после обновления пакетов, патч пишет `99-security.ini` в `apache2/conf.d`. Тесты 304 → 371. Найдены все 8 намеренных мутаций в коде.^[inferred]

2. **Реализация #10 (auto-update keeper).** Второй субагент: три этапа keeper: пин дистро-веток PHP (Priority -1), выполнение сухого запуска, запись `Allowed-Origins` в `/etc/apt/apt.conf.d/51php2shell-ppa-origins`. Тесты 371 → 448, 9 из 9 мутаций.

3. **Решение: Apache restart vs graceful.** После замечания о downtime (несколько секунд упадут все сайты Apache, не только PHP) я спросил владельца. Решение:留ить `systemctl restart apache2`, поскольку fix оператор запускает сознательно в выбранный час. Риск документирован в SKILL.md и описании PR.

4. **Полный обзор (review-2axis).** Параллельно два рецензента: стандарты и спецификация. Требуемые нарушения в обоих осях. Стандарты: 2 пункта (не упомянут `branch.sh` в шапке, exit коды incomplete). Спецификация: 4 требуемых + 2 опциональных.

5. **Фиксация из обзора.** Субагент ремонта: 17 пунктов из плана, затем владелец просит 18-й (атомарность записи origin файла). Все багы — реальные; тесты их пропустили. Примеры: проба Apache на неверном порту, keeper допускал разные origin'ы при перезаписи, дублирование в unattended-upgrades. Тесты 510/510.^[inferred]

6. **Реализация #21 (origin из apt-cache policy).** Третий субагент переписал `branch.sh` и `fix.sh`, чтобы получать источник из `apt-cache policy`, а не из версии пакета. На Debian trixie это различие видно: версия `8.4.11-1` без пометки, но политика указывает архив. Тесты 510 → 521. Мержит в main коммитом 871d778.

**Выход:**

- Success. PRD #1 целиком на main: комминиты bb2f2dc (PR #19: #9 + #10 + ремонты) и 871d778 (PR #24: #21).
- Тикеты #2-#10 закрыты, 510 → 521 тестов.
- Четыре follow-up тикета (#20-#23): `.htaccess` overrides, рефакторинги из обзора, первый запуск mod_php на живом хосте.
- Архитектурное решение (restart vs graceful) документировано как trade-off.

**Уроки:**

1. **Двухосевый обзор ловит разные классы багов.** Стандарты поймали ошибки документации и exit кодов, спецификация — логику (неверный порт для проб, нарушение инвариантов состояния).^[inferred]

2. **Субагенты через TDD дают полноту и мутационную верификацию.** 26 мутаций за три тикета (#9, #10, #21), все найдены существующими или новыми тестами; даже комментарии в коде правильные.^[inferred]

3. **Атомарность записи файла — не микрооптимизация.** Если процесс прерывается, truncated `/etc/apt/apt.conf.d/51php2shell-ppa-origins` сломает apt parse. Решение: пишем `.php2shell-new`, потом `mv`. Владелец заметил после базовой ремонта.^[inferred]

4. **Origin из политики vs версии.** Пакеты без дополнительной пометки в версии (8.4.11-1) обманывают простой парсер, но apt-cache policy всегда имеет источник. Надежнее полагаться на политику.

## Related

- [[project/php2shell-fixer]]