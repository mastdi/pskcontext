/*
 * Copyright (c) 2023 Martin Storgaard Dieu <martin@storgaarddieu.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "_pskcontext.h"

char _pskcontextfunc_docs[] = "Hello world description.";

PyMethodDef _pskcontext_funcs[] = {
	{	"openssl_version_number",
		(PyCFunction)openssl_version_number,
		METH_NOARGS,
		_pskcontextfunc_docs
	},
	{ NULL}
};

char _pskcontext_docs[] = "This module provides a binding to OpenSSL methods used for PSK SSL connections.";

PyModuleDef _pskcontext_mod = {
	PyModuleDef_HEAD_INIT,
	"_pskcontext",
	_pskcontext_docs,
	-1,
	_pskcontext_funcs,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC PyInit__pskcontext(void) {
	return PyModule_Create(&_pskcontext_mod);
}
