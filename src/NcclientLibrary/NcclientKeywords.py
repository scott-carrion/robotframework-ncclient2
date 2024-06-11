#!/usr/bin/env python

import re
from ncclient import manager
from ncclient.xml_ import to_ele
import ncclient.operations
from robot.api import logger
from robot.libraries.DateTime import convert_time
import robot

_standard_capabilities = {
    # Whether or not the NETCONF server supports the <candidate/> database
    "candidate" : False,

    # Whether or not the NETCONF server supports confirmed commits
    # A confirmed commit is reverted if there is no follow-up commit within
    # a configurable interval. See IETF RFC 6241 for more information
    "confirmed-commit" : False,

    # Whether or not the NETCONF server accepts remote procedure calls (RPCs)
    "interleave" :  False,

    # Whether or not the NETCONF server supports basic notification delivery
    "notification": False,

    # Whether or not the NETCONF server supports <partial-lock> and
    # <partial-unlock>
    "partial-lock" : False,

    # Whether or not to roll back a configuration change if an edit-config
    # operation failed
    "rollback-on-error" : False,

    # Whether or not the NETCONF server supports the <startup/> database
    "starup" : False,

    # Indicates file, https and sftp server capabilities
    "url" : False,

    # Whether or not the NETCONF server supports the <validate> operation
    "validate" : False,

    # Whether or not the NETCONF server allows the client to change the running
    # configuration directly (i.e. no need to commit candidate DB to running DB)
    "writable-running" : False,

    # Whether or not the NETCONF server fully supports the XPATH 1.0
    # specification for filter data
    "xpath" : False
}

# TODO(scarrion): Come up with some proper handling for NcclientExceptions
class NcclientException(Exception):
    pass


class NcclientKeywords(object):
    """NcclientLibrary2 is a Robot Framework library for interacting with a NETCONF device using ``ncclient``.

       This library supports various essential NETCONF operations on a server:

       - Query of operational data on a network element, with subtree and xpath filtering support

       - Query of configurational data on a network element, with subtree and xpath filtering support

       - Execution of supported commands on a network element (remote procedure calls, also known as RPCs)

       - Various other operations that NETCONF implements, such as configuration datastore copying, are also supported

       - Full synchronous and asynchronous support for all of the above

       - Subscription to notification streams on a network element, with subtree and xpath filtering support

       This library is semantically similar to the popular ``SSHLibrary`` and ``BuiltIn.Telnet`` libraries in that
       active connections are identified using an alias. However, unlike these libraries, the alias must be specified
       every time instead of using a special ``Switch Connection`` keyword. This is a conscious design choice meant
       to eliminate ambiguity that often confuses users when multiple concurrent connections are active.

       This library is intended to stand alongside the other two aforementioned libraries as the de facto standard
       interface for interacting with network elements over the NETCONF protocol using Robot Framework.

       = Synchronous vs Asynchronous Behavior =
       Synchronous/asynchronous behavior is handled per NETCONF session.

       When a NETCONF session is in synchronous mode, all operations are governed by a global synchronization timeout,
       which can be queried and configured via the ``Get Sync Mode`` and ``Set Sync Mode`` keywords, respectively.
       See the individual documentation for those keywords for more information on how to get/set this timeout value.

       When a NETCONF session is in asynchronous mode, instead of returning a reply to the caller, the ``RPC`` object
       is stored internally in a hash table (pythonic dictionary) and the relevant keyword returns almost immediately,
       as opposed to waiting for a reply or timeout as in synchronous mode.

       All keywords that support asynchronous mode require an argument when so enabled that associates the particular
       operation with a name. That is, the ``async_name`` that is provided is used as a key in the internal dictionary
       which holds all the launched asynchronous commands, and the ``RPC`` object is the value. For Robot's purposes,
       though, access to this object is not really useful. The keyword ``Get Async Command Status`` extends a mechanism to
       access this dictionary, so that it is possible to query the status and response of launched asynchronous commands.
       The caller of this keyword can launch an arbitrary number of asynchronous commands on any number of sessions, then
       poll (check-and-wait) results if desired.

       === How Collisions Are Handled ===
       Any valid Robot/python string can be used as a command invocation's ``async_name``, even one that has already been
       used.

       If the same name is used twice, the new ``RPC`` *will overwrite the old one*. So, take care to use different names
       for commands if you need to refer to the results of the old one later!
    """
    ROBOT_LIBRARY_SCOPE = 'Global'

    def __init__(self):
        self._cache = robot.utils.ConnectionCache('No sessions created')

        # XXX TODO: REMOVE THIS AS WE HANDLE THIS ON A PER-CONNECTION BASIS NOW
        # Whether operations are executed asynchronously (True) or
        # synchronously (False) (the default).
        self.async_mode = False

        # The timeout for synchronous RPC requests.
        self.timeout = None

        # Which errors are raised as RPCError exceptions. Valid values
        # are the constants defined in RaiseMode. The default value is ALL.
        self.raise_mode = None

        # Capabilities object representing the client's capabilities
        self.client_capabilities = None

        # Capabilities object representing the server's capabilities
        self.server_capabilities = _standard_capabilities

        # YANG modules supported by the NETCONF server
        self.yang_modules = None

        # session-id assigned by the NETCONF server
        self.session_id = None

        # Whether or not there is an active connection to the NETCONF server
        self.connected = None

        # Dictionary for asynchronous commands
        # When an asynchronous command is launched, it is associated with a name and stored for later
        # Test code will access this dictionary to check the status and response of async commands
        self.async_op_dict = {}

    def connect(self, *args, **kwds):
        """
        Initialize a connection with a NETCONF server using ncclient manager over SSH transport.

         ``host`` is the host to connect to. Can be an IP or a hostname.

         ``port`` is the port that NETCONF over SSH is hosted on. 830 by default.

         ``username`` is the username to use for SSH authentication.

         ``password`` is the password to use for SSH authentication.

         ``look_for_keys`` is a boolean that determines whether or not to look for SSH keys when connecting.

         ``key_filename`` is the path to file where private key is stored, if desired.

        Note that all NETCONF connections are initialized in synchronous mode, with a default timeout decided by the server.

        To change the synchronous mode timeout and/or change the connection to asynchronous mode, see keyword ``Set Sync Mode``.
        """

        try:
            logger.info('Creating session. Args and kwargs follow: %s, %s' % (args, kwds))
            alias = kwds.get('alias')
            session = manager.connect(
                host=kwds.get('host'),
                port=int(kwds.get('port') or 830),
                username=str(kwds.get('username')),
                password=str(kwds.get('password')),
                hostkey_verify=False,
                look_for_keys= False if str(kwds.get('look_for_keys')).lower() == 'false' else True,
                key_filename=str(kwds.get('key_filename')),
            )
            self._cache.register(session, alias=alias)
            all_server_capabilities = session.server_capabilities
            self.client_capabilities = session.client_capabilities
            self.session_id = session.session_id
            self.connected = session.connected
            self.timeout = session.timeout
            # Store YANG Modules and Capabilities
            self.yang_modules, server_capabilities = \
                    self._parse_server_capabilities(all_server_capabilities)
            # Parse server capabilities
            for sc in server_capabilities:
                self.server_capabilities[sc] = True

            logger.debug("Server capabilities follow after newline:\n%s\n\n" \
                         "Server YANG modules follow after newline:\n%s\n\n" \
                         "Client capabilities follow after newline:\n%s\n\n" \
                         "Session timeout (in seconds) follows after newline:\n%s"
                         %(self.server_capabilities, self.yang_modules, self.client_capabilities, self.timeout))
            return True
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def get_server_capabilities(self):
        """ Returns capabilities of the current NETCONF server. Requires an open NETCONF connection """
        return self.server_capabilities

    def get_yang_modules(self):
        """ Returns supported YANG modules of the current NETCONF server. Requires an open NETCONF connection"""
        return self.yang_modules

    def _parse_server_capabilities(self, server_capabilities):
        """
        Returns server_capabilities and supported YANG modules in JSON format
        """
        module_list = []
        server_caps = []
        try:
            for sc in server_capabilities:
                # urn:ietf:params:netconf:capability:{name}:1.x
                server_caps_match = re.match(
                        r'urn:ietf:params:netconf:capability:(\S+):\d+.\d+',
                        sc)
                if server_caps_match:
                    server_caps.append(server_caps_match.group(1))
                modules_match = re.findall(
                    r'(\S+)\?module=(\S+)&revision=' +
                    '(\d{4}-\d{2}-\d{2})&?(features=(\S+))?',
                    sc)
                if modules_match:
                    namespace, name, revision, _, features = modules_match[0]
                    if features:
                        module_list.append(
                            {"name": name, "revision": revision,
                            "namespace": namespace,
                            "features": features.split(",")})
                    else:
                        module_list.append({"name":name,
                                            "revision":revision,
                                            "namespace": namespace})

            module_dict = {"module-info": module_list}
            return module_dict, server_caps
        except NcclientException as e:
            logger.error(list(server_capabilities))
            logger.error(str(e))
            raise str(e)

    def _register_async_op(self, async_name, obj, op_type):
        """Internal helper function that registers a given RPC object with the chosen name in the async_op_dict for later recall"""

        # First, check to make sure that the async_name was set. If it wasn't, throw an error as we need a key for the dictionary entry and won't continue without it
        if not async_name:
            raise ValueError("NETCONF session is in asynchronous mode, but async_name for this operation was not specified")

        logger.info("Asynchronous %s operation launched with id '%s'" % (op_type, async_name))

        # Store the object in the dictionary. We assume that the user knows what they're doing, and allow overwriting of dictionary entries
        # For traceability, though, we will print a line in the log if an overwrite is done
        if async_name in self.async_op_dict:
            logger.info("Asynchronous operation with this id already exists. Overwriting it")

        self.async_op_dict[async_name] = obj
        logger.info("Asynchronous %s operation context object stored successfully" % op_type)

    def get_config(self, alias, source='running', filter_type='subtree',
                   filter_criteria=None, async_name=None):
        """
        Retrieve all or part of a specified configuration.

        ``alias`` is the name of the ``Session`` object in the cache to query.

        ``source`` is the name of the configuration datastore being queried. Default value is ``running``.

        ``filter_type`` is the type of filter to apply to the configuration query. Must be either ``xpath`` or ``subtree``.

        ``filter_criteria`` is the filter itself. Depending on ``filter_type``, this can be either a string representation of an xpath or a string representation of an XML subtree.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        gc_filter = None
        try:
            if filter_criteria:
                gc_filter = (filter_type, filter_criteria)

            logger.info("Getting configurational info from NETCONF server with connection alias '%s'\n" \
                        "Getting from datastore (source): '%s'\n" \
                        "Tuple representation of filter to use follows after newline:\n%s"
                        % (alias, source, gc_filter))

            # Get the data. It doesn't matter at this point if we are running synchronously or not
            gotc = session.get_config(source, gc_filter)

            # If we are running synchronously, we can return the data member of what the get_config call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return gotc.data

            self._register_async_op(async_name, gotc, "GET CONFIG")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def edit_config(self, alias, config, target='candidate', default_operation='merge',
                    test_option='test-then-set', error_option='rollback-on-error', format='xml', async_name=None):
        """
        Load all or part of the specified config to the target
         configuration datastore.

        ``alias`` is the name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore being edited. Default is ``candidate``.

        ``config`` is the configuration, itself that will be applied to the ``target`` datastore. This must be an XML rooted in the config
        element.  It can be specified either as a string or an Element.

        ``default_operation`` is the behavior when comitting a change to the NE configuration. Must be ``merge``, ``replace``, or ``None``. Default is ``merge``.

        ``test_option`` is the behavior when applying a change to to the NE configuration. Must be ``set`` or ``test-then-set``. Default is ``test-then-set``.

        ``error_option`` is the behavior when an error is encountered. Must be either ``stop-on-error``, ``continue-on-error``, or ``rollback-on-error``. Default is ``rollback-on-error``.

	    ``format`` is the format of the configuration. Must be either  ``xml``, ``text``, or ``url``. Default is ``xml``.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)

        try:
            logger.info("Editing configuration of NETCONF server with connection alias '%s'\n" \
                        "Editing datastore (target): '%s'\n" \
                        "Configuration to apply follows after newline:\n%s\n" \
                        "Default operation to use for commit of this config edit: '%s'\n" \
                        "Test operation to use for commit of this config edit: '%s'\n" \
                        "Error operation to use in the case of failed commit of this config edit: '%s'" 
                        % (alias, target, config, default_operation, test_option, error_option))

            # Send the edit. It doesn't matter at this point if we are running synchronously or not
            edited = session.edit_config(config, format, target, default_operation, test_option, error_option)

            # If we are running synchronously, what the edit_config call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return edited

            self._register_async_op(async_name, edited, "EDIT CONFIG")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def copy_config(self, alias, source, target, async_name=None):
        """
        Create or replace an entire configuration datastore with the contents
        of another complete configuration datastore.

        ``alias`` is the name of the Session object in the cache to use.

        ``source`` is the name of the configuration datastore to use as the
        source of the copy operation or config element containing the
        configuration subtree to copy.

        ``target`` is the name of the configuration datastore to use as the
        destination of the copy operation.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Copying entire configuration of NETCONF server with connection alias '%s'\n" \
                        "Source datastore for copy (source): '%s'\n" \
                        "Destination datastore for copy (target): '%s'"
                        % (alias, source, target))

            # Execute the copy. It doesn't matter at this point if we are running synchronously or not
            cp = session.copy_config(source, target)

            # If we are running synchronously, we can return the data member of what the get call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return cp

            self._register_async_op(async_name, cp, "COPY CONFIG")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def delete_config(self, alias, target, async_name=None):
        """
        Delete a configuration datastore.

        ``alias`` is the name of the Session object in the cache to use.

        ``target`` is the name or URL of configuration datastore to delete.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Deleting entire configuration of NETCONF server with connection alias '%s'\n" \
                        "Datastore to delete (target): '%s'"
                        % (alias, target))

            # Execute the delete. It doesn't matter at this point if we are running synchronously or not
            deleted = session.delete_config(target)

            # If we are running synchronously, we can return the data member of what the get call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return deleted

            self._register_async_op(async_name, deleted, "DELETE CONFIG")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def dispatch_rpc(self, alias, rpc, source=None, filter=None, async_name=None):
        """
        Dispatch of RPC to NETCONF server.

        ``alias`` is the name of the Session object in the cache to use.

        ``rpc`` is the plain text XML of the RPC to be dispatched.

        ``source`` is the name of the configuration datastore being queried. This is only relevant if you're manually crafting an RPC to ``get-config`` or similar.
                   For most applications, this doesn't need to be set.
                   Default value is ``None``

        ``filter`` is the portion of the configuration to retrieve. This is only relevant if you're manually crafting an RPC to ``get``, ``get-config``, or similar.
                   For most applications, this doesn't need to be set.
                   Default value is ``None``

        ``async_name``  is the name to associate this RPC execution with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)

        try:
            logger.info("Dispatching remote procedure call (RPC) to NETCONF server with connection alias '%s'\n" \
                        "RPC to to be dispatched follows after newline:\n%s\n" \
                        "Datastore to target (source): '%s'\n" \
                        "Filter to use follows after newline:\n'%s'" 
                        % (alias, rpc, source, filter))

            # Dispatch the RPC. It doesn't matter at this point if we are running synchronously or not
            dispatched = session.dispatch(to_ele(rpc), source, filter)

            # If we are running synchronously, we can return what the dispatch call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return dispatched

            self._register_async_op(async_name, dispatched, "generic RPC")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def lock(self, alias, target, async_name=None):
        """
        Make a client-side requeset to lock the configuration system of a device.

        ``alias`` is the name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore to lock.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Attempting to acquire lock of a datastore on NETCONF server with connection alias: '%s'" \
                        "Datastore to lock (target): '%s'"
                        % (alias, target))

            # Try to acquire the lock. It doesn't matter at this point if we are running synchronously or not
            locked = session.lock(target)

            # If we are running synchronously, we can return what the lock call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return locked

            self._register_async_op(async_name, locked, "DATASTORE LOCK")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def unlock(self, alias, target, async_name=None):
        """
        Release a configuration lock, previously obtained with the lock
        operation.

        ``alias`` is the name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore to unlock.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Attempting to release lock of a datastore on NETCONF server with connection alias: '%s'" \
                        "Datastore to unlock (target): '%s'"
                        % (alias, target))

            # Try to release the lock. It doesn't matter at this point if we are running synchronously or not
            unlocked = session.unlock(target)

            # If we are running synchronously, we can return what the unlock call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return unlocked

            self._register_async_op(async_name, unlocked, "DATASTORE UNLOCK")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def locked(self, alias, target, async_name=None):
        """
        Return a context manager for a lock on a datastore, where target
        is the name of the configuration datastore to lock.

        ``alias`` is the name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore to unlock.

        ``async_name``  is name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Querying if a datastore is locked on NETCONF server with connection alias: '%s'" \
                        "Datastore to query about (target): %s"
                        % (alias, target))

            # Send the lock query. It doesn't matter at this point if we are running synchronously or not
            is_locked = session.locked(target)

            # If we are running synchronously, we can return what the locked call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return is_locked

            self._register_async_op(async_name, is_locked, "DATASTORE LOCK QUERY")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def get(self, alias, filter_type='subtree', filter_criteria=None, async_name=None):
        """
        Retrieve running configuration and device state information.

        ``alias`` is the name of the Session object in the cache to use.

        ``filter_type`` is the type of filter to apply to the configuration query. Must be either ``xpath`` or ``subtree``. Default value is ``subtree``

        ``filter_criteria`` is the filter itself. Depending on ``filter_type``, this can be either a string representation of an xpath or a string representation of an XML subtree. Pass None to apply no filter. Default is ``None``.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*

        Returns raw plaintext XML reply from NETCONF server if in synchronous mode, else ``None``.
        """
        session = self._cache.switch(alias)
        get_filter = None
        try:
            if filter_criteria:
                get_filter = (filter_type, filter_criteria)

            logger.info("Getting operational data from NETCONF server with connection alias '%s'\n" \
                        "Tuple representation of filter to use follows after newline:\n%s"
                        % (alias, get_filter))

            # Get the data. It doesn't matter at this point if we are running synchronously or not
            got = session.get(get_filter)

            # If we are running synchronously, we can return the data member of what the get call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return got.data

            self._register_async_op(async_name, got, "GET")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def close_session(self, alias):
        """
        Request graceful termination of the specified NETCONF session, and also close the
        transport.

        ``alias`` is the name of the Session object in the cache to gracefully close.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Gracefully closing NETCONF session with server with connection alias: '%s'\n"
                        % (alias))
            session.close_session()
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def kill_session(self, alias, session_id):
        """
        Force the termination of a NETCONF session by session ID.

        ``alias`` is the name of the Session object in the cache to forcefully kill.

        ``session_id`` is the session identifier of the NETCONF session to be
                       terminated as a string.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, session_id: %s" %(alias, session_id))
            logger.info("Killing NETCONF session with server with connection alias: '%s'\n" \
                        "NETCONF session ID to kill: '%s'"
                        % (alias, session_id))
            session.kill_session(session_id)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def commit(self, alias, confirmed=False, timeout=None, async_name=None):
        """
        Commit the ``candidate`` configuration as the device's new ``running``
        configuration. Depends on the ``:candidate`` capability.

        A confirmed commit (i.e. if confirmed is ``True``) is reverted if there is
        no followup commit within the timeout interval. If no timeout is
        specified the confirm timeout defaults to 600 seconds (10 minutes). A
        confirming commit may have the confirmed parameter but this is not
        required. Depends on the ``:confirmed-commit`` capability.

        ``alias`` is the name of the Session object in the cache to use.

        ``confirmed`` is a boolean that determines whether this is a confirmed commit.

        ``timeout`` specifies the confirm timeout. This value must be in Robot Framework's time format (e.g. ``1 minute``, ``2 min 3 s``, ``4.5``)
                    that is explained in an appendix of the Robot Framework User Guide.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.
        """
        session = self._cache.switch(alias)

        # The timeout parameter will be interpreted as a string. It is expected that this is a time format recognized by Robot Framework that can be converted using its API
        # to representation of seconds for passing to ncclient
        converted_timeout = None
        if timeout:
            converted_timeout = convert_time(timeout, result_format='number')
        try:
            logger.info("Attempting commit of candidate datastore to running datastore on NETCONF server with connection alias '%s'\n" \
                        "Confirmed commit flag: %s\n" \
                        "Confirmed commit timeout: %s\n" \
                        % (alias, confirmed, converted_timeout))

            # Execute the commit. It doesn't matter at this point if we are running synchronously or not
            committed = session.commit(confirmed, converted_timeout)

            # If we are running synchronously, we can return what the commit call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return committed

            self._register_async_op(async_name, committed, "COMMIT")


        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def discard_changes(self, alias, async_name=None):
        """
        Revert the candidate configuration to the currently running
        configuration. Any uncommitted changes are discarded.

        ``alias`` is the name of the Session object in the cache to use.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.
        """
        session = self._cache.switch(alias)
        try:
            logger.info("Attempting discard of changes to candidate datastore on NETCONF server with connection alias '%s'"
                        % alias)

            # Execute the discard. It doesn't matter at this point if we are running synchronously or not
            discarded = session.discard_changes()

            # If we are running synchronously, we can return what the commit call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return discarded

            self._register_async_op(async_name, discarded, "DISCARD CANDIDATE DB CHANGES")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def validate(self, alias, source, async_name=None):
        """
        Validate the contents of the specified configuration.

        ``alias`` is the name of the Session object in the cache to use.

        ``source`` is the name of the configuration datastore being validated or
        config element containing the configuration subtree to be validated.

        ``async_name``  is the name to associate this operation with for later reference. This parameter is only relevant if the specified active NETCONF session
                        is in asynchronous mode.
                        Default value is ``None`` for convenience when running in synchronous mode, but *it is required if in asynchronous mode*.

        """
        session = self._cache.switch(alias)
        try:
            logger.info("Attempting validation of a datastore on NETCONF server with connection alias '%s'\n" \
                        "Datastore to validate or config XML to validate follows after newline:\n%s\n"
                        % (alias, confirmed, converted_timeout))

            # Execute the validation. It doesn't matter at this point if we are running synchronously or not
            validated = session.validate(source)

            # If we are running synchronously, we can return what the commit call does. If synchronous timeout occurs, an error will be raised which should be handled by the caller
            if not session.async_mode:
                return validated

            self._register_async_op(async_name, validated, "VALIDATE DATASTORE")

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def subscribe(self, alias, stream_name=None, filter_type='subtree', filter_criteria=None, start_time=None, stop_time=None):
        """
        Subscribe to a NETCONF notification stream with a configurable filter.

        This keyword sends a NETCONF event notification subscription request (``<create-subscription>`` as defined in IETF RFC5277) to a NETCONF server.

        Note that this keyword does not take any notifications from the server. It merely creates the subscription. For retrieving notifications, see keyword "Get Notification"

        ``alias`` is the name of the Session object in the cache to use.

        ``stream_name`` is the stream name to subscribe to. Most servers implement only a single default notification stream. Pass ``None`` to request the default. Default value is ``None``

        ``filter_type`` is the type of filter to apply to the notification stream. Must be either ``xpath``, ``subtree``, or ``custom``.
                        Filters with type ``xpath`` or ``subtree`` have the ``filter`` element of the NETCONF XML request pre-defined and formatted by ncclient.
                        Thus, the ``filter_criteria`` only needs to contain the data that goes *inside* the filter element.
                        Filters with type ``custom`` are expected to define and format the ``filter`` element in the ``filter_criteria``.
                        Default value is ``subtree``

        ``filter_criteria`` is the NETCONF XML filter itself, expressed as a string. Depending on ``filter_type``, this can be either a string representation of an xpath or a string representation of an XML subtree.
                            Pass ``None`` to apply no filter.
                            Default value is ``None``.

        ``start_time`` is the lower bound of time from which notifications should be reported. See IETF RFC5277. This time should be a string representation of a timestamp compliant with RFC3339.
                       Pass ``None`` to specify no start time. Default value is ``None``.

        ``stop_time`` is the upper bound of time to which notifications should be reported. See IETF RFC5277. This time should be a string representation of a timestamp compliant with RFC3339.
                      Pass ``None`` to specify no stop time. Default value is ``None``.

        Returns ``None``.
        """
        session = self._cache.switch(alias)
        subscribe_filter = None
        try:
            if filter_criteria:
                # If filter_type was "custom", then we will pass the filter criteria directly to create_subscription. It's expected that the caller included the filter element already
                if filter_type == "custom":
                    subscribe_filter = filter_criteria

                # Otherwise, filter_type was "subtree" or "xpath". We can pass a tuple to create_subscription and ncclient will format the filter element
                else:
                    subscribe_filter = (filter_type, filter_criteria)

            # Create the subscription
            logger.info("Attempting subscription to notification stream on NETCONF server with connection alias '%s'\n" \
                        "Stream name to subscribe to (if empty, default stream was chosen): '%s'\n" \
                        "Filter to use follows after newline:\n%s"
                        "Notification stream start time: '%s'\n" \
                        "Notification stream stop time: '%s'\n" \
                        % (alias, stream_name, subscribe_filter, start_time, stop_time))
            session.create_subscription(filter=subscribe_filter, stream_name=stream_name, start_time=start_time, stop_time=stop_time)

        # If any exceptions are encountered during the above steps, print it to the Robot log and re-raise the error so that it is properly reported as a failure
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def get_notification(self, alias, block=True, timeout=None):
        """
        Attempt to retrieve a *single* NETCONF notification (as defined in IETF RFC5277) from a server.

        This keyword assumes that a subscription has *already been created*. For subscription creation, see keyword ``Subscribe``.

        If a NETCONF notification stream replay was requested by specifying the ``start_time`` and/or ``stop_time`` parameters, then a ``replayComplete`` notification will be received at some point.
        The caller of this keyword should know when to expect this notification and handle it properly.

        ``alias`` is the name of the Session object in the cache to use.

        ``block`` is a boolean which dictates whether or not to wait for a notification. Default value is ``True``.

        ``timeout`` is how long to wait for a notification before returning. This parameter is only meaningful if ``block`` is ``True``.
                    Pass ``None`` to block indefinitely. 
                    Default value is ``None``.
                    If timeout expires prior to any notification being received, ``None`` is returned.

        Returns raw plaintext XML reply from NETCONF server, or ``None`` if no notification could be retrieved. This could be because timeout occurred, or ``block`` was ``False`` and no notification was available.
        """
        session = self._cache.switch(alias)

        # The timeout parameter will be interpreted as a string. It is expected that this is a time format recognized by Robot Framework that can be converted using its API
        # to representation of seconds for passing to ncclient
        converted_timeout = None
        if timeout:
            converted_timeout = convert_time(timeout, result_format='number')

        try:
            # Attempt to retrieve a single notification, blocking if so configured, with the specified timeout
            logger.info("Attempting fetch of single notification from subscribed stream on NETCONF server with connection alias '%s'\n" \
                        "Block flag: '%s'\n" \
                        "Timeout (in seconds): '%s'\n" \
                        % (alias, block, converted_timeout))
            ret = session.take_notification(block=block, timeout=converted_timeout)

            # If ret is None, timeout occurred and we should return none.
            # Otherwise, it would be some Notification object which we can unpack and return as an XML string for parsing by the caller
            return ret.notification_xml if ret else None

        # If any exceptions are encountered during the above steps, print it to the Robot log and re-raise the error so that it is properly reported as a failure
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def get_sync_mode(self, alias):
        """
        Fetch both settings relevant to synchronization behavior for a specified NETCONF connection.

        These settings are returned in a dictionary with keys and values explained below:

        ``is_async`` is a boolean flag that dictates the current sync mode. If ``True``, all operations performed over this connection are done asynchronously.
                     If ``False``, all operations performed over this connection are done synchronously.

        ``sync_mode_timeout`` is how long to wait for a synchronous operation to complete before raising a ``TimeoutExpiredError``.
                              This value must be in Robot Framework's time format (e.g. ``1 minute``, ``2 min 3 s``, ``4.5``)
                              that is explained in an appendix of the Robot Framework User Guide.
                              This parameter is irrelevant if the NETCONF session is running in asynchronous mode (i.e. if ``is_async`` is ``True``).
                              Set to ``None`` to wait for synchronous operations to complete indefinitely. 

        """
        session = self._cache.switch(alias)
        return {"is_async": session.async_mode, "sync_mode_timeout": session.timeout}

    def set_sync_mode(self, alias, mode=None, sync_mode_timeout='donotset'):
        """
        Configure (a)synchronous behavior for the specified active NETCONF connection.

        ``mode`` is the synchronization mode to apply to the specified connection. Must be either ``sync`` (for synchronous mode) or ``async`` (for asynchronous mode).
                 Set to ``None`` and the sync mode will not be changed.
                 Default value is ``None``

        ``sync_mode_timeout`` is how long to wait for a synchronous operation to complete before raising a ``TimeoutExpiredError``.
                              This value must be in Robot Framework's time format (e.g. ``1 minute``, ``2 min 3 s``, ``4.5``)
                              that is explained in an appendix of the Robot Framework User Guide.
                              This parameter is irrelevant if the NETCONF session is running in asynchronous mode.
                              Set to ``None`` to wait for synchronous operations to complete indefinitely.
                              Set to the exact string ``donotset`` and the timeout for synchronous operations will not be changed
                              Default value is the special string ``donotset``
        """
        session = self._cache.switch(alias)
        logger.info("Editing sync mode parameters for connection to NETCONF server with alias '%s'" % alias)

        # First, handle the mode parameter
        if mode == "sync":
            logger.info("Activating synchronous mode (set is_async to False)")
            session.async_mode = False

        elif mode == "async":
            logger.info("Activating asynchronous mode (set is_async to True)")
            session.async_mode = True

        # If mode was set to None, this is a valid choice: We do nothing and move on!
        elif mode is None:
            logger.info("Mode was not changed (value of is_async == %s)" % str(session.async_mode))

        # Raise an exception if the mode was anything else
        else:
            raise ValueError("Unknown synchronization mode '" + mode + "'")

        # Finally, handle sync_mode_timeout
        if sync_mode_timeout == "donotset":
            logger.info("Synchronous mode timeout was not changed (value of timeout == %s seconds)" % str(session.timeout))

        # If sync_mode_timeout was anything except this special string, we set it
        else:
            # None is a supported value. If the parameter was None, don't treat is as a Robot Framework time and try to convert it
            converted_timeout = None
            if sync_mode_timeout:
                # The timeout parameter will be interpreted as a string. It is expected that this is a time format recognized by Robot Framework that can be converted using its API
                # to representation of seconds for passing to ncclient
                converted_timeout = convert_time(sync_mode_timeout, result_format='number')
                logger.info("Setting synchronous mode timeout to %s seconds" % str(converted_timeout))
            else:
                logger.info("Disabling synchronous mode timeout (set to None)")

            # Whether we are using None or a converted value, if execution reached this point, we can set the synchronous timeout for the current connection
            session.timeout = converted_timeout

    def get_async_command_status(self, async_name):
        """
        Poll the status of a previously launched asynchronous command.

        Returns a dictionary with three elements, whose keys and values are explained below.

        ``done_flag`` maps to a boolean that indicates whether or not the operation has actually completed. If ``False``, the other values in the tuple are undefined.

        ``reply_xml`` maps to the plain text XML reply to the asynchronous command from the server.

        ``error`` maps to a string representation of any error reported regarding the RPC. ``None`` if there was no error reported.
        """

        # Simply construct the dictionary and return it. If the name doesn't exist, a NameError will raise and should be handled by the caller
        obj = self.async_op_dict[async_name]

        # When an asynchronous request is made, we expect that the type stored was a generic RPC object. We also handle RPCErrors if exception raising (raise_mode) is disabled
        if isinstance(obj, ncclient.operations.RPC):
            return {"done_flag": obj.event.is_set(), "reply_xml": obj.reply, "error": obj.error}

        if isinstance(obj, ncclient.operations.RPCError):
            return {"done_flag": True, "reply_xml": obj.xml, "error": obj.errlist}

        else:
            raise ValueError("Operation object stored was not a recognized type! Its type was: '" + str(type(obj)))
