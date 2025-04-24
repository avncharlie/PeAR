.PHONY: hook clean
all: drivers

drivers:
	# normal + persistent drivers
	gcc -c -O3 -fPIC pear_driver.c
	ar rcs libPeARDriver.a pear_driver.o
	# shmem driver + hook
	gcc -c -O3 -fPIC pear_shmem_driver.c
	ar rcs libPeARShmemDriver.a pear_shmem_driver.o
	gcc -c -O3 shmem_driver_hook/hook.c
clean:
	rm *.a *.o
