import os
import sys
import json

docs_path = sys.argv[1]


def get_markdown_file(dir_config, base_path):
    current_files = []
    for row in dir_config:
        if row.get('path'):
            current_files.append(
                f'{base_path}/README.md' if row['path'] == './'
                else f'{base_path}/{row["path"]}.md'
            )
        if row.get('children'):
            current_files += get_markdown_file(row['children'], base_path)
    return current_files


if __name__ == '__main__':
    r = open(f'{docs_path}/directory.json', 'r')
    directory_config = json.load(r)
    markdown_files = get_markdown_file(directory_config['cn'], f'{docs_path}/zh_CN')
    markdown_files += get_markdown_file(directory_config['en'], f'{docs_path}/en_US')

    for file_path, dir_list, file_list in os.walk(docs_path):
        for file_name in file_list:
            if not file_name.endswith('.md'):
                continue
            if os.path.join(file_path, file_name) not in markdown_files:
                print(f'Remove {os.path.join(file_path, file_name)}')
                os.remove(os.path.join(file_path, file_name))
