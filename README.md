# MePKI
Small PKI project


# Коротко о правилах 

1. Имеет смысл создать в репозитории под каждый кусок отдельные папки - client, server, ca, algorithms, etc. 
2. Лучше выделять на каждую конкретную задачу свою ветку, про именование будет сказано чуть ниже.

!! ОЧЕНЬ полезно прочитать это перед работой с гитом: [https://git-scm.com/docs/giteveryday](https://git-scm.com/docs/giteveryday)

# Порядок коммитов в репозиторий 

1. `git fetch`
2. `git checkout master`
3. `git pull`
4. `git checkout -b old-branch new-branch`
5. `git commit -a -m "..."`
6. `git rebase -i origin/master`
7. `git push --force origin new-branch`

Обязательно почитать про команды checkout, commit, rebase!

После команды push на сайте создаётся pull request в соответствующем меню. После его создания изменения визуально оцениваются и вливаются в репозиторий кнопкой Merge.

# Как подтянуть репозиторий себе

`git clone https://Aoxomoxoa@bitbucket.org/Aoxomoxoa/pki.git *foldername*`
По умолчанию (без указания foldername) репозиторий подтянется в ту папку, где была выполнена команда

# Некоторые крайне полезные команды:

`git status` - показывает, какие файлы в каком состоянии находятся
`git add` - добавление новых файлов в коммит

# Именование веток
1. Имя ветки - 2-5 слов, разделённые дефисом. Исключение - первые коммиты по той или иной части PKI, именуются как initial-\*element name\*. Например, initial-client, initial-ca, initial-algorithms
2. Первое слово характеризует название элемента PKI, следующие 1-4 - кратко описывают суть ветки. Например, client-add-crl-check, alrogithms-add-rsa-support etc
3. Если ветка выделяется сиключительно для исправления какой-либо ошибки в коде - целесообразно вторым словом ставить слово "hotfix". Пример: client-hotfix-cert-validation, algorithms-hotfix-rsa-generation

# Gitignore

Изначально стоит создать файл .gitignore, куда нужно внести все файлы, отслеживание которых крайне нежелательно - приватные ключи, конфиги и прочее. При этом, если файлы необходимы - рекомендуется добавлять в репозиторий их шаблоны или примеры с расширением .example (cert.pem -> cert.pem.example)

# Дополнительно

Если требуются какие-либо уточнения по работе с гитом, стоит пройтись по этим ссылкам:

1. [Учебник по Git (en)](https://git-scm.com/book/en/v2/Getting-Started-About-Version-Control) 
2. [То же самое, но на русском](https://git-scm.com/book/ru/v1/%D0%92%D0%B2%D0%B5%D0%B4%D0%B5%D0%BD%D0%B8%D0%B5) 
3. [Git Cheat Sheet](https://education.github.com/git-cheat-sheet-education.pdf) 
4. [Git Cheat Sheet 2](https://gist.github.com/prograhammer/81cac393bf599e69f825)
4. [Another Git Cheat Sheet](https://www.git-tower.com/blog/git-cheat-sheet/)

Также рекомендую настроить credential helper, чтобы не вбивать постоянно пароль ручками (только в процессе коммита это придётся сделать не меньше 3 раз).
