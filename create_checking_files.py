import os

string_to_write = "test" * 1000000

check_files = set()

directories = ["C:\\",str(os.environ["HOMEPATH"]),"C:\\Program Files (x86)","C:\\Program Files","C:\\Users","C:\\Windows","C:\\Windows\System32"]
for directory in directories:
    for i in range(100):
        print(directory)
        file_path = directory+"\\test_file"+str(i)+".pdf"
        check_files.add(file_path)
        file_path = directory+"\\test_file"+str(i)+".exe"
        check_files.add(file_path)
        
for file_path in check_files:
    print(file_path)
    with open(file_path,"w") as file:
        file.write(string_to_write)
