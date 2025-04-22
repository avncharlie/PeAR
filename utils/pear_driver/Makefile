.PHONY: hook clean
all: drivers

drivers:
	# normal + persistent drivers
	gcc -c -fPIC pear_driver.c
	ar rcs libPeARDriver.a pear_driver.o
	# shmem driver + hook
	gcc -c -fPIC pear_shmem_driver.c
	ar rcs libPeARShmemDriver.a pear_shmem_driver.o
	gcc -c shmem_driver_hook/hook.c
clean:
	rm *.a *.o
