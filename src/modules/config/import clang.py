import clang.cindex

# Set this to the actual path of your libclang.dll
clang_path = r"C:\Program Files\LLVM\bin\libclang.dll"

# Set the path for libclang
clang.cindex.Config.set_library_file(clang_path)

# Now print the version
print(clang.cindex.Config.library_file)
print(clang.cindex.conf.lib.clang_getClangVersion().decode())
