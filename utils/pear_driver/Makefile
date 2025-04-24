.PHONY: hook clean
all: drivers

drivers:
	# stdin driver
	gcc -c -O3 -fPIC pear_stdin_driver.c
	ar rcs libPeARStdinDriver.a pear_stdin_driver.o
	gcc -c -O3 -fPIC pear_file_driver.c
	ar rcs libPeARFileDriver.a pear_file_driver.o
	# shmem driver + hook
	gcc -c -O3 -fPIC pear_shmem_driver.c
	ar rcs libPeARShmemDriver.a pear_shmem_driver.o
	gcc -c -O3 shmem_driver_hook/hook.c
clean:
	rm *.a *.o
