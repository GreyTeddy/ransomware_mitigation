import os

string_to_write = "test" * 1000000

check_files = set()

directories = ["C:\\",str(os.environ["HOMEPATH"]),"C:\\Program Files (x86)","C:\\Program Files","C:\\Users"]
for directory in directories:
    for i in range(100):
        print(directory)
        file_path = directory+"\\!!!!test_file"+str(i)+".pdf"
        check_files.add(file_path)
        file_path = directory+"\\!!!!test_file"+str(i)+".exe"
        check_files.add(file_path)

counter = 0
for file_path in check_files:
    if not os.path.exists(file_path):
        counter += 1

print(counter,len(check_files))