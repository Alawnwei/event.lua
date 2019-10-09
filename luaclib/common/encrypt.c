#include "encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <errno.h>



uint16_t
checksum(uint16_t* addr, size_t size) {
	uint32_t sum = 0;
	while (size > 1) {
		sum += *addr++;
		size -= 2;
	}
	if (size > 0) {
		sum += *(uint8_t*)addr;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (int16_t)~sum;
}

uint8_t*
message_encrypt(uint16_t* wseed, uint16_t id, const uint8_t* message, size_t size) {
	uint16_t total = sizeof(uint16_t) * 3 + size;
	uint8_t* data = malloc(total);

	memcpy(data, (uint8_t*)&total, sizeof(uint16_t));
	uint8_t* reserve = data + sizeof(uint16_t);
	memcpy(data + sizeof(uint16_t) * 2, (uint8_t*)&id, sizeof(uint16_t));
	memcpy(data + sizeof(uint16_t) * 3, message, size);

	uint16_t* addr = (uint16_t*)(data + sizeof(uint16_t) * 2);
	size_t length = total - sizeof(uint16_t) * 2;

	uint32_t sum = 0;
	while (length > 1) {
		uint16_t tmp = *addr;

		sum += tmp;

		*addr = tmp ^ (*wseed);
		*wseed += tmp;

		addr++;

		length -= 2;
	}
	if (length > 0) {
		uint8_t tmp = *(uint8_t*)addr;
		sum += tmp;
		*(uint8_t*)addr = tmp ^ (*wseed);
		*wseed += tmp;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	*(uint16_t*)reserve = (uint16_t)~sum;

	return data;
}

int
message_decrypt(uint16_t* rseed, uint8_t* message, size_t size) {
	if (size < sizeof(uint16_t) * 2) {
		return -1;
	}

	uint16_t* data = (uint16_t*)message;

	uint32_t sum = data[0];
	uint16_t* addr = &data[1];
	size_t length = size - sizeof(uint16_t);
	while (length > 1) {
		uint16_t tmp = *addr;

		*addr = tmp ^ (*rseed);
		*rseed += *addr;

		sum += *addr;

		addr++;

		length -= 2;
	}
	if (length > 0) {
		uint8_t* data = (uint8_t*)addr;
		uint8_t tmp = *data;

		*data = tmp ^ (*rseed);
		*rseed += *data;

		sum += *data;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	if ((uint16_t)~sum != 0) {
		return -1;
	}
	return 0;
}
