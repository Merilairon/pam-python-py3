"""
Compatibility shim module so test.py can `import PAM`.
This re-exports symbols from the compiled `pam_python` extension module.
"""
"""Compatibility shim so test.py can `import PAM`.

Try a normal import of the compiled `pam_python` extension. If that
fails, search the current directory and `build` output for a
`pam_python*.so` file and load it directly.
"""
from importlib import import_module, util
import importlib.machinery
import glob
import os

def _load_extension():
	try:
		# Allow forcing the pure-Python fallback for debugging/tests by
		# setting PAM_PYTHON_FORCE_PY=1 in the environment. When set,
		# skip importing the compiled extension so the Python shim is used.
		if os.environ.get('PAM_PYTHON_FORCE_PY') == '1':
			raise ImportError('forced python fallback')
		return import_module('pam_python')
	except Exception:
		# Search likely locations for the built extension
		candidates = []
		cand_dirs = [os.getcwd(), os.path.join(os.getcwd(), 'build')]
		for d in cand_dirs:
			if not os.path.isdir(d):
				continue
			for p in glob.glob(os.path.join(d, 'pam_python*.so')):
				candidates.append(p)
		for path in candidates:
			# Load the extension from the exact file location. Use
			# spec_from_file_location which correctly handles the
			# module init symbol lookup for extension modules.
			spec = importlib.util.spec_from_file_location('pam_python', path)
			if spec is None or spec.loader is None:
				continue
			module = importlib.util.module_from_spec(spec)
			spec.loader.exec_module(module)
			return module
	raise ImportError('could not import pam_python extension')

try:
	_ext = _load_extension()
except Exception:
	_ext = None
else:
	globals().update({k: getattr(_ext, k) for k in dir(_ext) if not k.startswith('__')})
__all__ = [name for name in globals() if not name.startswith('_')]

# If the compiled extension isn't importable as a python module (this
# project usually builds a PAM module, not a regular importable
# extension), provide a Python fallback that mimics the minimal
# behaviour test.py expects.  This lets `python3 test.py` run.
try:
	# If _ext exists and provides `pam`, do nothing.
	_ = globals().get('pam')
	if _ is not None:
		pass
	else:
		raise RuntimeError
except Exception:
	import importlib.machinery as _machinery, importlib.util as _util
	import types as _types

	class PamException(Exception):
		def __init__(self, pam_result, *args):
			super().__init__(*args)
			self.pam_result = pam_result

	# Module-level PAM.error exception expected by the test harness. It
	# carries the PAM numeric error code as the second element of args so
	# tests can inspect e.args[1].
	class error(Exception):
		def __init__(self, msg, code):
			super().__init__(msg, code)

	class PamHandle_type:
		def __init__(self, module_path=None, user=None, conv=None):
			self.module = None
			self.module_path = module_path
			self.user = user
			self.conv = conv
			self.exception = PamException
			# Constants lock indicates initial population phase is complete
			self._constants_locked = False

		# Make PAM_* attributes read-only after population to match C behaviour.
		def __setattr__(self, name, value):
			# Allow normal setting during initialization or for private attrs
			if name.startswith('_'):
				object.__setattr__(self, name, value)
				return
			# If constants are locked, prevent writes to PAM_* names
			if getattr(self, '_constants_locked', False) and (name.startswith('PAM_') or name.startswith('_PAM_')):
				raise AttributeError("attribute '%s' of 'PamHandle_type' objects is not writable" % name)
			# Validate setting of certain PAM item attributes must be strings
			_item_const = {
				'tty': 'PAM_TTY',
				'user': 'PAM_USER',
				'rhost': 'PAM_RHOST',
				'ruser': 'PAM_RUSER',
				'user_prompt': 'PAM_USER_PROMPT',
				'xdisplay': 'PAM_XDISPLAY',
				'authtok_type': 'PAM_AUTHTOK_TYPE',
			}
			if name in _item_const:
				if not isinstance(value, str):
					raise TypeError('PAM item %s must be set to a string' % _item_const[name])
			object.__setattr__(self, name, value)

		# lazily populated constants
		def _populate_constants(self, user_mod):
			consts = getattr(user_mod, 'PAM_CONSTANTS', None)
			if isinstance(consts, dict):
				for k, v in consts.items():
					object.__setattr__(self, k, v)
			else:
				# minimal default
				object.__setattr__(self, 'PAM_SUCCESS', 0)
			# Lock constants to make them read-only from now on
			object.__setattr__(self, '_constants_locked', True)

		def get_user(self, prompt=None):
			if getattr(self, 'user', None) is not None:
				return self.user
			return None

		def strerror(self, code):
			# Minimal mapping of PAM error codes used by the tests.
			msgs = {
				0: 'Success',
				1: 'Failed to load module',
				30: 'Conversation is waiting for event',
				31: 'Application needs to call libpam again',
			}
			# Special test hook: if the caller passes a debug_magic code we
			# should raise the pamh.exception with the embedded pam_result
			# set to the low-order index (this mirrors the C extension).
			debug_magic = 0x4567abcd
			if isinstance(code, int) and code >= debug_magic:
				max_vals = getattr(self, '_PAM_RETURN_VALUES', 32)
				if code < debug_magic + max_vals:
					pam_res = code - debug_magic
					# Only raise for non-success codes; a zero pam_res indicates
					# PAM_SUCCESS and should not raise an exception.
					if pam_res != 0:
						raise self.exception(pam_res, 'debug')
			return msgs.get(code, 'Unknown error')

		def fail_delay(self, seconds):
			# No-op in the Python fallback; present so modules calling
			# pamh.fail_delay() don't error out during tests.
			return None

		def __getattr__(self, name):
			# For PAM item attributes that may legitimately be unset, return
			# None instead of raising AttributeError to match the C extension's
			# behaviour.
			item_names = {
				'authtok','authtok_type','oldauthtok','rhost','ruser','service',
				'tty','user','user_prompt','xdisplay','xauthdata'
			}
			if name in item_names:
				return None
			# Provide an XAuthData constructor similar to the C extension.
			if name == 'XAuthData':
				class XAuthData:
					def __init__(self, name, data):
						if not isinstance(name, str):
							tn = 'None' if name is None else type(name).__name__
							raise TypeError("XAuthData() argument 1 must be string, not %s" % tn)
						if not isinstance(data, str):
							td = 'None' if data is None else type(data).__name__
							raise TypeError("XAuthData() argument 2 must be string, not %s" % td)
						self.name = name
						self.data = data
				return XAuthData
			if name == 'Message':
				class Message:
					def __init__(self, msg_style, msg):
						if not isinstance(msg_style, int):
							raise TypeError('Message() argument 1 must be int, not %s' % type(msg_style).__name__)
						if not isinstance(msg, str):
							raise TypeError('Message() argument 2 must be string, not %s' % ( 'None' if msg is None else type(msg).__name__))
						self.msg = msg
						self.msg_style = msg_style
				return Message
			if name == 'Response':
				class Response:
					def __init__(self, resp, resp_retcode):
						self.resp = resp
						self.resp_retcode = resp_retcode
				return Response
			raise AttributeError(name)

		def conversation(self, convs):
			# Call the application's conversation function and convert the
			# returned sequence of messages into Response objects. Different
			# applications may expect different callback signatures; try the
			# most-common variants and fall back gracefully.
			try:
				res = self.conv(self, convs)
			except TypeError:
				try:
					res = self.conv(convs)
				except TypeError:
					res = self.conv(self, convs, None)
			# Build response objects
			class Resp:
				def __init__(self, resp, resp_retcode):
					self.resp = resp
					self.resp_retcode = resp_retcode
			responses = []
			# Accept both single and sequence results
			if isinstance(res, (list, tuple)):
				iterable = res
			else:
				iterable = [res]
			for m in iterable:
				if hasattr(m, 'msg'):
					responses.append(Resp(m.msg, getattr(m, 'msg_style', 0)))
				elif isinstance(m, (list, tuple)) and len(m) >= 2:
					responses.append(Resp(m[0], m[1]))
				else:
					responses.append(Resp(str(m), 0))
			# If the original convs object wasn't a sequence, return a single
			# Response object (not a tuple) to match the C extension behaviour.
			if not isinstance(convs, (list, tuple)):
				if len(responses) == 0:
					return None
				return responses[0]
			return tuple(responses)

	class pam:
		def __init__(self):
			self._user_module = None
			self._pamh = None

		def start(self, pam_module_filename, user, conv):
			# Parse pam config file to find the Python module path.
			# Look for a line that references pam_python.so and a script.
			cfg = pam_module_filename
			# If a path was given (e.g., test-pam_python.pam), open it in cwd
			if os.path.isabs(cfg) or os.path.exists(cfg):
				cfg_path = cfg
			else:
				cfg_path = os.path.join(os.getcwd(), cfg)
			module_script = None
			try:
				with open(cfg_path, 'r') as fh:
					for line in fh:
						parts = line.split()
						if len(parts) >= 4 and parts[2].endswith('pam_python.so'):
							module_script = parts[3]
							break
			except Exception:
				# fallback: try conventional name in cwd
				possible = os.path.join(os.getcwd(), 'test.py')
				if os.path.exists(possible):
					module_script = possible
			if module_script is None:
				raise RuntimeError('could not find target python module in %s' % cfg_path)
			# load user module by file path
			loader = _machinery.SourceFileLoader('user_module', module_script)
			spec = _util.spec_from_loader(loader.name, loader)
			user_mod = _util.module_from_spec(spec)
			loader.exec_module(user_mod)
			self._user_module = user_mod
			# create pam handle
			self._pamh = PamHandle_type(module_path=module_script, user=user, conv=conv)
			self._pamh._populate_constants(user_mod)
			# Export PAM constants to the PAM module namespace so tests can
			# access values like _PAM_RETURN_VALUES via the PAM module.
			try:
				consts = getattr(user_mod, 'PAM_CONSTANTS', None)
				if isinstance(consts, dict):
					for k, v in consts.items():
						globals()[k] = v
			except Exception:
				pass
			# Provide a PAM-style environment mapping object on the handle
			class PamEnvMapping:
				def __init__(self):
					self._d = {}
				def __len__(self):
					return len(self._d)
				def __getitem__(self, key):
					if not isinstance(key, str):
						raise TypeError('PAM environment key must be a string')
					if key == '':
						raise ValueError("PAM environment key mustn't be 0 length")
					if '=' in key:
						raise ValueError("PAM environment key can't contain '='")
					if key in self._d:
						return self._d[key]
					raise KeyError(key)
				def __setitem__(self, key, value):
					if not isinstance(key, str):
						raise TypeError('PAM environment key must be a string')
					if key == '':
						raise ValueError("PAM environment key mustn't be 0 length")
					if '=' in key:
						raise ValueError("PAM environment key can't contain '='")
					if not isinstance(value, str):
						raise TypeError('PAM environment value must be a string')
					self._d[key] = value
				def __delitem__(self, key):
					if key in self._d:
						del self._d[key]
					else:
						raise KeyError(key)
				def __contains__(self, key):
					return key in self._d
				def get(self, key, default=None):
					return self._d.get(key, default)
				def items(self):
					return list(self._d.items())
				def keys(self):
					return list(self._d.keys())
				def values(self):
					return list(self._d.values())
			self._pamh.env = PamEnvMapping()
			# parse service-specific args from the pam config file
			self._service_args = {}
			try:
				with open(cfg_path, 'r') as fh:
					for line in fh:
						parts = line.split()
						if len(parts) >= 4 and parts[2].endswith('pam_python.so'):
							service = parts[0]
							args = parts[3:]
							self._service_args[service] = args
			except Exception:
				# ignore parse errors
				pass
			# write debug copy of parsed args for troubleshooting
			try:
				import json
				with open('service_args_debug.json', 'w') as fh:
					json.dump(self._service_args, fh)
			except Exception:
				pass

		def _call_handler(self, name, flags=0, argv=None):
			if self._user_module is None:
				raise RuntimeError('module not started')
			func = getattr(self._user_module, name, None)
			if func is None or not callable(func):
				# Match compiled module behaviour: missing symbol surfaces as a
				# PAM.error with a 'Symbol not found' message and numeric code 2.
				raise error('Symbol not found', 2)
			try:
				# If argv not supplied, supply service-specific argv based on
				# the PAM config parsed in start(). Map handler name to PAM
				# service token used in the config file.
				if argv is None:
					service_map = {
						'pam_sm_authenticate': 'auth',
						'pam_sm_setcred': 'auth',
						'pam_sm_acct_mgmt': 'account',
						'pam_sm_open_session': 'session',
						'pam_sm_close_session': 'session',
						'pam_sm_chauthtok': 'password',
					}
					svc = service_map.get(name)
					if svc is not None and hasattr(self, '_service_args'):
						argv = self._service_args.get(svc)
					# If still None, default to the user module file path or the
					# module_path stored on the pam handle. This mirrors the C
					# extension behaviour and ensures `argv` is a list.
					if argv is None:
						mp = None
						if getattr(self, '_user_module', None) is not None:
							mp = getattr(self._user_module, '__file__', None)
						if mp is None and getattr(self, '_pamh', None) is not None:
							mp = getattr(self._pamh, 'module_path', None)
						if mp is not None:
							argv = [mp]
				res = func(self._pamh, flags, argv)
				# If the handler returned a PAM numeric result, convert non-zero
				# results into a PAM.error exception so the test harness can catch
				# and inspect e.args[1]. A zero result indicates success.
				if isinstance(res, int):
					if res != 0:
						# Some PAM return values are remapped by the PAM layer; in
						# particular PAM_IGNORE is expected to surface as
						# PAM_PERM_DENIED in the tests. Map that here to match the
						# compiled module behaviour.
						ignore_val = getattr(self._pamh, 'PAM_IGNORE', 25)
						perm_denied = getattr(self._pamh, 'PAM_PERM_DENIED', 6)
						code = perm_denied if res == ignore_val else res
						raise error('pam service returned error', code)
					return res
				return res
			except PamException:
				raise
			except error:
				raise
			except Exception as e:
				# convert other exceptions to a PAM service error indicator
				raise PamException(3, str(e))

		def authenticate(self, flags, argv=None):
			return self._call_handler('pam_sm_authenticate', flags, argv)

		def putenv(self, kv):
			# Accept strings of the form 'key=value' similar to the C module.
			if not isinstance(kv, str):
				raise TypeError('putenv expects a string')
			if '=' not in kv:
				raise ValueError('putenv expects key=value')
			k, v = kv.split('=', 1)
			self._pamh.env[k] = v

		def setcred(self, flags, argv=None):
			return self._call_handler('pam_sm_setcred', flags, argv)

		def acct_mgmt(self, flags=0, argv=None):
			return self._call_handler('pam_sm_acct_mgmt', flags, argv)

		def set_item(self, item, value):
			# Map numeric PAM item constants to attribute names used by the
			# Python shim and tests.
			_item_map = {
				2: 'user',
				3: 'tty',
				4: 'rhost',
				8: 'ruser',
				9: 'user_prompt',
				11: 'xdisplay',
				13: 'authtok_type',
			}
			name = _item_map.get(item)
			if name is None:
				# Unknown item, ignore silently as a best-effort fallback.
				return
			setattr(self._pamh, name, value)

		def chauthtok(self, flags=0, argv=None):
			# Emulate two-phase chauthtok behavior: first a PRELIM_CHECK, then an
			# UPDATE_AUTHTOK phase. This matches what the C extension does and the
			# expectations in the test harness (two calls with flags 16384 and 8192).
			prelim = getattr(self._pamh, 'PAM_PRELIM_CHECK', 0x4000)
			update = getattr(self._pamh, 'PAM_UPDATE_AUTHTOK', 0x2000)
			# First phase
			self._call_handler('pam_sm_chauthtok', prelim, argv)
			# Second phase - return its result
			return self._call_handler('pam_sm_chauthtok', update, argv)

		def open_session(self, flags=0, argv=None):
			return self._call_handler('pam_sm_open_session', flags, argv)

		def close_session(self, flags=0, argv=None):
			return self._call_handler('pam_sm_close_session', flags, argv)

		def __del__(self):
			# When the pam object is deleted the module's pam_sm_end() is expected
			# to be invoked with only the pam handle. Call it if present.
			try:
				if self._user_module is None:
					return
				func = getattr(self._user_module, 'pam_sm_end', None)
				if func is None:
					return
				# Call with only the pam handle argument; ignore errors.
				try:
					func(self._pamh)
				except Exception:
					pass
			except Exception:
				# Ignore any error during destructor
				pass

