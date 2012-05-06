/*
 * windows libusb0-win32 backend for libusbx 1.0
 * Copyright © 2009-2012 Pete Batard <pete@akeo.ie>
 * With contributions from Michael Plante, Orin Eman et al.
 * Parts of this code adapted from libusb-win32-v1 by Stephan Meyer
 * Hash table functions adapted from glibc, by Ulrich Drepper et al.
 * Major code testing contribution by Xiaofan Chen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <libusbi.h>
#include "libusb0_win32_driver_api.h"
#include "poll_windows.h"
#include <fcntl.h>

const uint64_t epoch_time = UINT64_C(116444736000000000);	// 1970.01.01 00:00:000 in MS Filetime

struct libusb0_win32_device_priv
{
	HANDLE hFile;
	char device_desc[DEVICE_DESC_LENGTH];
};

struct libusb0_win32_transfer_priv
{
	libusb_request req;
	struct winfd fd;
};

static int libusb_sys_init(struct libusb_context *ctx)
{
	return LIBUSB_SUCCESS;
}

static void libusb_sys_exit(void)
{
}

static int sync_device_io_control(HANDLE hFile, DWORD dwControlCode, void const * in_data, int in_len, void * out_data, int out_len)
{
	OVERLAPPED o;
	HANDLE hEvent;
	DWORD dwReturned = 0;

	hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	if (hEvent == NULL)
		return LIBUSB_ERROR_NO_MEM;

	memset(&o, 0, sizeof o);
	o.hEvent = hEvent;

	if (!DeviceIoControl(hFile, dwControlCode, (void *)in_data, in_len, out_data, out_len, &dwReturned, &o))
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			if (!GetOverlappedResult(hFile, &o, &dwReturned, TRUE))
			{
				CloseHandle(hEvent);
				return LIBUSB_ERROR_IO;
			}
		}
		else
		{
			CloseHandle(hEvent);
			return LIBUSB_ERROR_IO;
		}
	}

	CloseHandle(hEvent);
	return dwReturned;
}

static int get_descriptor(HANDLE hFile, int type, int index, int langid, void * buf, int len)
{
	libusb_request req = {0};
	req.descriptor.type = type;
	req.descriptor.index = index;
	req.descriptor.language_id = langid;

	return sync_device_io_control(hFile, LIBUSB_IOCTL_GET_DESCRIPTOR, &req, sizeof req, buf, len);
}

static int libusb_sys_get_device_list(struct libusb_context *ctx, struct discovered_devs **discdevs)
{
	int i;
	WCHAR buf[32];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	struct libusb_device * dev;
	struct libusb0_win32_device_priv * priv_dev;
	int dev_count = 0;
	int r = LIBUSB_SUCCESS;
	struct discovered_devs * new_discdevs = NULL;

	for (i = 1; i < 256; ++i)
	{
		wsprintf(buf, L"\\\\.\\libusb0-%04d", i);

		hFile = CreateFile(buf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			continue;

		dev = usbi_get_device_by_session_id(ctx, i);
		if (!dev)
		{
			dev = usbi_alloc_device(ctx, i);
			if (!dev)
			{
				CloseHandle(hFile);
				return LIBUSB_ERROR_NO_MEM;
			}

			priv_dev = (struct libusb0_win32_device_priv *)&dev->os_priv;
			priv_dev->hFile = hFile;

			dev->bus_number = 0;
			dev->device_address = i;

			r = get_descriptor(hFile, 1, 0, 0, priv_dev->device_desc, sizeof priv_dev->device_desc);
			if (r != DEVICE_DESC_LENGTH)
				r = LIBUSB_ERROR_IO;
			if (r < 0)
			{
				libusb_unref_device(dev);
				return r;
			}

			r = usbi_sanitize_device(dev);
			if (r < 0)
			{
				libusb_unref_device(dev);
				return r;
			}
		}
		else
		{
			// We already have a handle opened and stored in libusb_device
			CloseHandle(hFile);
		}

		new_discdevs = discovered_devs_append(*discdevs, dev);
		libusb_unref_device(dev);
		if (!new_discdevs)
			return LIBUSB_ERROR_NO_MEM;

		*discdevs = new_discdevs;
		++dev_count;
	}

	return dev_count;
}

static int libusb_sys_open(struct libusb_device_handle *handle)
{
	return LIBUSB_SUCCESS;
}

static void libusb_sys_close(struct libusb_device_handle *handle)
{
}

static int libusb_sys_get_device_descriptor(struct libusb_device *device, unsigned char *buffer, int *host_endian)
{
	struct libusb0_win32_device_priv * priv_dev = (struct libusb0_win32_device_priv *)device->os_priv;
	memcpy(buffer, priv_dev->device_desc, DEVICE_DESC_LENGTH);
	*host_endian = 1;
	return LIBUSB_SUCCESS;
}

static int libusb_sys_get_active_config_descriptor(struct libusb_device *device, unsigned char *buffer, size_t len, int *host_endian)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int libusb_sys_get_config_descriptor(struct libusb_device *device, uint8_t config_index, unsigned char *buffer, size_t len, int *host_endian)
{
	// TODO: this should be cached, apparently
	struct libusb0_win32_device_priv * priv_dev = (struct libusb0_win32_device_priv *)device->os_priv;
	*host_endian = 1;
	return get_descriptor(priv_dev->hFile, 2, config_index, 0, buffer, len);
}

static int libusb_sys_get_configuration(struct libusb_device_handle *handle, int *config)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int libusb_sys_set_configuration(struct libusb_device_handle *handle, int config)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int libusb_sys_claim_interface(struct libusb_device_handle *handle, int interface_number)
{
	struct libusb0_win32_device_priv * priv_dev = (struct libusb0_win32_device_priv *)handle->dev->os_priv;

	libusb_request req = {0};
	req.intf.interface_number = interface_number;

	return sync_device_io_control(priv_dev->hFile, LIBUSB_IOCTL_CLAIM_INTERFACE, &req, sizeof req, 0, 0);
}

static int libusb_sys_release_interface(struct libusb_device_handle *handle, int interface_number)
{
	struct libusb0_win32_device_priv * priv_dev = (struct libusb0_win32_device_priv *)handle->dev->os_priv;

	libusb_request req = {0};
	req.intf.interface_number = interface_number;

	return sync_device_io_control(priv_dev->hFile, LIBUSB_IOCTL_RELEASE_INTERFACE, &req, sizeof req, 0, 0);
}

static int libusb_sys_set_interface_altsetting(struct libusb_device_handle *handle, int interface_number, int altsetting)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int libusb_sys_clear_halt(struct libusb_device_handle *handle, unsigned char endpoint)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static int libusb_sys_reset_device(struct libusb_device_handle *handle)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}

static void libusb_sys_destroy_device(struct libusb_device *dev)
{
	struct libusb0_win32_device_priv * priv_dev = (struct libusb0_win32_device_priv *)&dev->os_priv;
	CloseHandle(priv_dev->hFile);
}

static int libusb_sys_submit_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer * transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb0_win32_device_priv * priv_dev = (struct libusb0_win32_device_priv *)transfer->dev_handle->dev->os_priv;
	struct libusb0_win32_transfer_priv * priv_transfer = usbi_transfer_get_os_priv(itransfer);
	struct libusb_context * ctx = transfer->dev_handle->dev->ctx;
	struct libusb0_win32_context * priv_ctx = (struct libusb0_win32_context *)(ctx + 1);

	DWORD dwReturned, dwControlCode;
	void * out_data;
	DWORD out_len;

	struct winfd fd;

	memset(&priv_transfer->req, 0, sizeof priv_transfer->req);
	switch (transfer->type)
	{
	case LIBUSB_TRANSFER_TYPE_CONTROL:
		{
		if (transfer->length < 8)
			return LIBUSB_ERROR_INVALID_PARAM;

			memcpy(&priv_transfer->req.control, transfer->buffer, 8);

			out_data = transfer->buffer + 8;
			out_len = transfer->length - 8;
			if ((priv_transfer->req.control.RequestType & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN)
				dwControlCode = LIBUSB_IOCTL_CONTROL_READ;
			else
				dwControlCode = LIBUSB_IOCTL_CONTROL_WRITE;
		}
		break;
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT:
		{
			priv_transfer->req.endpoint.endpoint = transfer->endpoint;

			out_data = transfer->buffer;
			out_len = transfer->length; // TODO: this should be a multiple of the packet size
			if ((priv_transfer->req.control.RequestType & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN)
				dwControlCode = LIBUSB_IOCTL_INTERRUPT_OR_BULK_READ;
			else
				dwControlCode = LIBUSB_IOCTL_INTERRUPT_OR_BULK_WRITE;
		}
		break;
	default:
		return LIBUSB_ERROR_NOT_SUPPORTED;
	}

	fd = usbi_create_fd(priv_dev->hFile, _O_RDONLY);
	if (fd.fd == INVALID_WINFD.fd)
		return LIBUSB_ERROR_NO_MEM;

	/*memset(&priv_transfer->o, 0, sizeof priv_transfer->o);
	priv_transfer->o.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	if (priv_transfer->o.hEvent == NULL)
		return LIBUSB_ERROR_NO_MEM;*/

	if (DeviceIoControl(priv_dev->hFile, dwControlCode, &priv_transfer->req, sizeof priv_transfer->req, out_data, out_len, &dwReturned, fd.overlapped))
	{
		if (transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL)
			itransfer->transferred = dwReturned + 8;
		else
			itransfer->transferred = dwReturned;

		usbi_handle_transfer_completion(itransfer, LIBUSB_TRANSFER_COMPLETED);
		usbi_free_fd(fd.fd);
	}
	else
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			usbi_free_fd(fd.fd);
			return LIBUSB_ERROR_IO;
		}

		priv_transfer->fd = fd;
		usbi_add_pollfd(ctx, fd.fd, POLLIN);
	}

	return LIBUSB_SUCCESS;
}

static int libusb_sys_cancel_transfer(struct usbi_transfer *itransfer)
{
	struct libusb_transfer * transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	struct libusb0_win32_transfer_priv * priv_transfer = usbi_transfer_get_os_priv(itransfer);

	if (!CancelIoEx(priv_transfer->fd.handle, priv_transfer->fd.overlapped)) // XXX: Windows XP
		return LIBUSB_ERROR_IO;

	return LIBUSB_SUCCESS;
}

static void libusb_sys_clear_transfer_priv(struct usbi_transfer *itransfer)
{

}

static int libusb_sys_handle_events(struct libusb_context *ctx, struct pollfd *fds, POLL_NFDS_TYPE nfds, int num_ready)
{
	struct libusb0_win32_transfer_priv * transfer_priv = NULL;
	struct usbi_transfer *transfer;
	int found = 0;
	POLL_NFDS_TYPE i;

	for (i = 0; i < nfds && num_ready; ++i)
	{
		if (!fds[i].revents)
			continue;

		num_ready--;

		usbi_mutex_lock(&ctx->flying_transfers_lock);
		list_for_each_entry(transfer, &ctx->flying_transfers, list, struct usbi_transfer) {
			transfer_priv = usbi_transfer_get_os_priv(transfer);
			if (transfer_priv->fd.fd == fds[i].fd) {
				found = 1;
				break;
			}
		}
		usbi_mutex_unlock(&ctx->flying_transfers_lock);

		if (found)
		{
			DWORD dwTransferred;
			DWORD error = 0;
			enum libusb_transfer_status status;

			usbi_remove_pollfd(ctx, transfer_priv->fd.fd);

			if (!GetOverlappedResult(transfer_priv->fd.handle, transfer_priv->fd.overlapped, &dwTransferred, FALSE))
			{
				error = GetLastError();
				transfer->transferred = 0;
			}
			else
			{
				transfer->transferred = dwTransferred;
			}

			switch (error)
			{
			case ERROR_OPERATION_ABORTED:
				status = LIBUSB_TRANSFER_CANCELLED;
				break;
			default:
				status = LIBUSB_TRANSFER_COMPLETED;
			}

			usbi_handle_transfer_completion(transfer, status);
			usbi_free_fd(transfer_priv->fd.fd);
			transfer_priv->fd = INVALID_WINFD;
		}
		else
		{
			return LIBUSB_ERROR_NOT_FOUND;
		}
	}

	return LIBUSB_SUCCESS;
}

static int libusb_sys_clock_gettime(int clkid, struct timespec *tp)
{
	switch (clkid)
	{
	case USBI_CLOCK_REALTIME:
		{
			SYSTEMTIME systemtime;
			FILETIME filetime;
			uint64_t time;

			GetSystemTime(&systemtime);
			SystemTimeToFileTime(&systemtime, &filetime);

			time = ((uint64_t)filetime.dwHighDateTime << 32) | filetime.dwLowDateTime;
			time -= epoch_time;

			tp->tv_sec = (long)(time / 10000000);
			tp->tv_nsec = (time % 10000000) * 100;
		}
		return LIBUSB_SUCCESS;
	case USBI_CLOCK_MONOTONIC:
		{
			DWORD tickcount = GetTickCount();
			tp->tv_sec = tickcount / 1000;
			tp->tv_nsec = (tickcount % 1000) * 1000000;
		}
		return LIBUSB_SUCCESS;
	default:
		return LIBUSB_ERROR_INVALID_PARAM;
	}
}

#ifdef USBI_TIMERFD_AVAILABLE
static clockid_t libusb_sys_get_timerfd_clockid(void)
{
	return LIBUSB_ERROR_NOT_SUPPORTED;
}
#endif

const struct usbi_os_backend libusb0_win32_backend = 
{
	"libusb0-win32",
	libusb_sys_init,
	libusb_sys_exit,
	libusb_sys_get_device_list,
	libusb_sys_open,
	libusb_sys_close,
	libusb_sys_get_device_descriptor,
	libusb_sys_get_active_config_descriptor,
	libusb_sys_get_config_descriptor,
	libusb_sys_get_configuration,
	libusb_sys_set_configuration,
	libusb_sys_claim_interface,
	libusb_sys_release_interface,
	libusb_sys_set_interface_altsetting,
	libusb_sys_clear_halt,
	libusb_sys_reset_device,
	0, // kernel_driver_active
	0, // detach_kernel_driver
	0, // attach_kernel_driver
	libusb_sys_destroy_device,
	libusb_sys_submit_transfer,
	libusb_sys_cancel_transfer,
	libusb_sys_clear_transfer_priv,
	libusb_sys_handle_events,
	libusb_sys_clock_gettime,

#ifdef USBI_TIMERFD_AVAILABLE
	libusb_sys_get_timerfd_clockid,
#endif

	sizeof(struct libusb0_win32_device_priv), // device_priv_size;
	0, // device_handle_priv_size;
	sizeof(struct libusb0_win32_transfer_priv), // transfer_priv_size;
	0, // add_iso_packet_size
};
