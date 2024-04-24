#!/usr/bin/env python

from ncclient import manager
from ncclient.xml_ import to_ele
from robot.api import logger
import re
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
    "roolback-on-error" : False,

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
    """Robot Framework library for interacting with a NETCONF device using ``ncclient``"""
    ROBOT_LIBRARY_SCOPE = 'Global'

    def __init__(self):
        self._cache = robot.utils.ConnectionCache('No sessions created')

        # Whether operations are executed asynchronously (True) or
        # synchronously (False) (the default).
        self.async_mode = None

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

    def connect(self, *args, **kwds):
        """
        Initialize a connection with a NETCONF server using ncclient manager over SSH transport.

         ``host`` The host to connect to. Can be an IP or a hostname

         ``port`` The port that NETCONF over SSH is hosted on. 830 by default

         ``username`` The username to use for SSH authentication

         ``password`` The password to use for SSH authentication

         ``look_for_keys`` Whether or not to look for SSH keys when connecting

         ``key_filename`` Path to file where private key is stored, if desired

        """

        try:
            logger.info('Creating session %s, %s' % (args, kwds))
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

            logger.debug("%s, %s, %s, %s" %(self.server_capabilities, 
                        self.yang_modules, self.client_capabilities,
                        self.timeout))
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

    def get_config(self, alias, source='running', filter_type='subtree',
                    filter_criteria=None):
        """
        Retrieve all or part of a specified configuration.

        ``alias`` Name of the Session object in the cache to query

        ``source`` Name of the configuration datastore being queried. Default is ``running``

        ``filter_type`` The type of filter to apply to the configuration query. Must be either ``xpath`` or ``subtree``

        ``filter_criteria`` The filter itself. Depending on ``filter_type``, this can be either a string representation of an xpath or a string representation of an XML subtree

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        gc_filter = None
        try:
            if filter_criteria:
                gc_filter = (filter_type, filter_criteria)

            logger.info("alias: %s, source: %s, filter: %s:" % (alias, source,
                                                                gc_filter))
            return session.get_config(source, gc_filter).data
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def edit_config(self, alias, config, target='candidate', default_operation='merge',
                    test_option='test-then-set', error_option='rollback-on-error', format='xml'):
        """
        Loads all or part of the specified config to the target
         configuration datastore.

        ``alias`` Name of the Session object in the cache to use.

        ``target`` Name of the configuration datastore being edited. Default is ``candidate``.

        ``config`` The configuration, itself that will be applied to the ``target`` datastore. This must be an XML rooted in the config
        element.  It can be specified either as a string or an Element.

        ``default_operation`` The behavior when comitting a change to the NE configuration. Must be "merge", "replace", or "none". Default is ``merge``.

        ``test_option`` The behavior when applying a change to to the NE configuration. Must be "set" or "test-then-set". Default is ``test-then-set``.

        ``error_option`` The behavior when an error is encountered. Must be either ``stop-on-error``, ``continue-on-error``, or ``rollback-on-error``. Default is ``rollback-on-error``.

	``format`` The format of the configuration. Must be either  ``xml``, ``text``, or ``url``. Default is ``xml``.

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)

        try:
            logger.info("target: %s, config: %s, default_operation: %s \
               test_option: %s,  error_option: %s" 
               % (target, config, default_operation, test_option, error_option))
            return session.edit_config(config, format, target, default_operation,
				     test_option, error_option)

        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def copy_config(self, alias, source, target):
        """
        Create or replace an entire configuration datastore with the contents
        of another complete configuration datastore.

        ``alias`` Name of the Session object in the cache to use.

        ``source`` Name of the configuration datastore to use as the
        source of the copy operation or config element containing the
        configuration subtree to copy

        ``target`` Name of the configuration datastore to use as the
        destination of the copy operation

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, source: %s, target: %s" % (alias, source,
                                                                target))
            return session.copy_config(source, target)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def delete_config(self, alias, target):
        """
        Delete a configuration datastore.

        ``alias`` Name of the Session object in the cache to use.

        ``target`` Name or URL of configuration datastore to delete.

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, target: %s" % (alias, target))
            return session.delete_config(target)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def dispatch_rpc(self, alias, rpc):
        """
        Dispatch of RPC to NETCONF server.

        ``alias`` Name of the Session object in the cache to use.

        ``rpc`` Plain text XML of the RPC to be dispatched

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, rpc: %s" % (alias, rpc))
            return session.dispatch(to_ele(rpc))
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def dispatch(self, alias, rpc_command, source=None, filter=None):
        """
        Generic dispatch of XML to NETCONF server.

        ``alias`` Name of the Session object in the cache to use.

        ``rpc_command`` RPC command to be dispatched either in plain
        text or in xml element format (depending on command)

        ``source`` Name of the configuration datastore being queried

        ``filter`` Portion of the configuration to retrieve
        (by default entire configuration is retrieved)

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, rpc_command: %s, source: %s, filter: %s" 
                                    % (alias, rpc_command, source, filter))
            return session.dispatch(rpc_command, source, filter)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def lock(self, alias, target):
        """
        Allows the client to lock the configuration system of a device.

        ``alias`` Name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore to lock

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, target: %s" % (alias, target))
            return session.lock(target)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def unlock(self, alias, target):
        """
        Release a configuration lock, previously obtained with the lock
        operation.

        ``alias`` Name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore to unlock

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, target: %s" % (alias, target))
            return session.unlock(target)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def locked(self, alias, target):
        """
        Returns a context manager for a lock on a datastore, where target
        is the name of the configuration datastore to lock.

        ``alias`` Name of the Session object in the cache to use.

        ``target`` is the name of the configuration datastore to unlock

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, target: %s" %(alias, target))
            return session.locked(target)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def get(self, alias, filter_type='subtree', filter_criteria=None):
        """
        Retrieve running configuration and device state information.

        ``alias`` Name of the Session object in the cache to use.

        ``filter_type`` The type of filter to apply to the configuration query. Must be either ``xpath`` or ``subtree``

        ``filter_criteria`` The filter itself. Depending on ``filter_type``, this can be either a string representation of an xpath or a string representation of an XML subtree

        Returns raw plaintext XML reply from NETCONF server
        """
        session = self._cache.switch(alias)
        get_filter = None
        try:
            if filter_criteria:
                get_filter = (filter_type, filter_criteria)
            return session.get(get_filter).data
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def close_session(self, alias):
        """
        Request graceful termination of the NETCONF session, and also close the
        transport.

        ``alias`` Name of the Session object in the cache to gracefully close.
        """
        session = self._cache.switch(alias)
        try:
            session.close_session()
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def kill_session(self, alias, session_id):
        """
        Force the termination of a NETCONF session.

        ``alias`` Name of the Session object in the cache to forcefully kill

        ``session_id`` Session identifier of the NETCONF session to be
        terminated as a string
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, session_id: %s" %(alias, session_id))
            session.kill_session(session_id)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    # TODO: ADD SUPPORT FOR ROBOT FRAMEWORK TIMES HERE, NOT JUST INTEGER SECONDS
    def commit(self, alias, confirmed=False, timeout=None):
        """
        Commit the ``candidate`` configuration as the device's new ``running``
        configuration. Depends on the :candidate capability.

        A confirmed commit (i.e. if confirmed is ``True``) is reverted if there is
        no followup commit within the timeout interval. If no timeout is
        specified the confirm timeout defaults to 600 seconds (10 minutes). A
        confirming commit may have the confirmed parameter but this is not
        required. Depends on the :confirmed-commit capability.

        ``alias`` Name of the Session object in the cache to use

        ``confirmed`` whether this is a confirmed commit

        ``timeout`` specifies the confirm timeout in seconds
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, confirmed: %s, timeout:%s" % (alias,
                                                            confirmed, timeout))
            return session.commit(confirmed, timeout)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def discard_changes(self, alias):
        """
        Revert the candidate configuration to the currently running
        configuration. Any uncommitted changes are discarded.

        ``alias`` Name of the Session object in the cache to use
        """
        session = self._cache.switch(alias)
        try:
            return session.discard_changes()
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)

    def validate(self, alias, source):
        """
        Validate the contents of the specified configuration.

        ``alias`` Name of the Session object in the cache to use

        ``source`` is the name of the configuration datastore being validated or
        config element containing the configuration subtree to be validated
        """
        session = self._cache.switch(alias)
        try:
            logger.info("alias: %s, source: %s" % (alias, source))
            return session.validate(source)
        except NcclientException as e:
            logger.error(str(e))
            raise str(e)
