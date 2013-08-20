import cPickle
import logging
from datetime import datetime

from beaker.container import NamespaceManager, Container
from beaker.exceptions import InvalidCacheBackendError, MissingCacheParameter
from beaker.synchronization import Synchronizer, _threading
from beaker.util import verify_directory, SyncDict

sa_version = None

log = logging.getLogger(__name__)

try:
    import sqlalchemy as sa
    import sqlalchemy.pool as pool
    from sqlalchemy import types
    sa_version = '0.3'
except ImportError:
    raise InvalidCacheBackendError("Database cache backend requires the 'sqlalchemy' library")

if not hasattr(sa, 'BoundMetaData'):
    sa_version = '0.4'

class DatabaseNamespaceManager(NamespaceManager):
    metadatas = SyncDict(_threading.Lock(), {})
    tables = SyncDict(_threading.Lock(), {})
    
    def __init__(self, namespace, url=None, sa_opts=None, optimistic=False,
                 table_name='beaker_cache', data_dir=None, lock_dir=None,
                 **params):
        """Creates a database namespace manager
        
        ``url``
            SQLAlchemy compliant db url
        ``sa_opts``
            A dictionary of SQLAlchemy keyword options to initialize the engine
            with.
        ``optimistic``
            Use optimistic session locking, note that this will result in an
            additional select when updating a cache value to compare version
            numbers.
        ``table_name``
            The table name to use in the database for the cache.
        """
        NamespaceManager.__init__(self, namespace, **params)
        
        if sa_opts is None:
            sa_opts = params
        
        if lock_dir is not None:
            self.lock_dir = lock_dir
        elif data_dir is None:
            raise MissingCacheParameter("data_dir or lock_dir is required")
        else:
            self.lock_dir = data_dir + "/container_db_lock"
        
        verify_directory(self.lock_dir)
        
        # Check to see if the table's been created before
        url = url or sa_opts['sa.url']
        table_key = url + table_name
        def make_cache():
            # Check to see if we have a connection pool open already
            meta_key = url + table_name
            def make_meta():
                if sa_version == '0.3':
                    if url.startswith('mysql') and not sa_opts:
                        sa_opts['poolclass'] = pool.QueuePool
                    engine = sa.create_engine(url, **sa_opts)
                    meta = sa.BoundMetaData(engine)
                else:
                    # SQLAlchemy pops the url, this ensures it sticks around
                    # later
                    sa_opts['sa.url'] = url
                    engine = sa.engine_from_config(sa_opts, 'sa.')
                    meta = sa.MetaData()
                    meta.bind = engine
                return meta
            meta = DatabaseNamespaceManager.metadatas.get(meta_key, make_meta)
            # Create the table object and cache it now
            cache = sa.Table(table_name, meta,
                             sa.Column('id', types.Integer, primary_key=True),
                             sa.Column('namespace', types.String(255), nullable=False),
                             sa.Column('accessed', types.DateTime, nullable=False),
                             sa.Column('created', types.DateTime, nullable=False),
                             sa.Column('data', types.BLOB(), nullable=False),
                             sa.UniqueConstraint('namespace')
            )
            cache.create(checkfirst=True)
            return cache
        self.hash = {}
        self._is_new = False
        self.loaded = False
        self.cache = DatabaseNamespaceManager.tables.get(table_key, make_cache)
    
    # The database does its own locking.  override our own stuff
    def do_acquire_read_lock(self): pass
    def do_release_read_lock(self): pass
    def do_acquire_write_lock(self, wait = True): return True
    def do_release_write_lock(self): pass
    
    def do_open(self, flags):
        # If we already loaded the data, don't bother loading it again
        if self.loaded:
            self.flags = flags
            return
        
        cache = self.cache
        result = sa.select([cache.c.data], 
                           cache.c.namespace==self.namespace
                          ).execute().fetchone()
        if not result:
            self._is_new = True
            self.hash = {}
        else:
            self._is_new = False
            try:
                self.hash = cPickle.loads(str(result['data']))
            except (IOError, OSError, EOFError, cPickle.PickleError):
                log.debug("Couln't load pickle data, creating new storage")
                self.hash = {}
                self._is_new = True
        self.flags = flags
        self.loaded = True
    
    def do_close(self):
        if self.flags is not None and (self.flags == 'c' or self.flags == 'w'):
            cache = self.cache
            if self._is_new:
                cache.insert().execute(namespace=self.namespace, 
                                       data=cPickle.dumps(self.hash),
                                       accessed=datetime.now(), 
                                       created=datetime.now())
                self._is_new = False
            else:
                cache.update(cache.c.namespace==self.namespace).execute(
                    data=cPickle.dumps(self.hash), accessed=datetime.now())
        self.flags = None
    
    def do_remove(self):
        cache = self.cache
        cache.delete(cache.c.namespace==self.namespace).execute()
        self.hash = {}
        
        # We can retain the fact that we did a load attempt, but since the
        # file is gone this will be a new namespace should it be saved.
        self._is_new = True

    def __getitem__(self, key): 
        return self.hash[key]

    def __contains__(self, key): 
        return self.hash.has_key(key)
        
    def __setitem__(self, key, value):
        self.hash[key] = value

    def __delitem__(self, key):
        del self.hash[key]

    def keys(self):
        return self.hash.keys()
        

class DatabaseContainer(Container):

    def do_init(self, data_dir=None, lock_dir=None, **params):
        self.funclock = None

    def create_namespace(self, namespace, url, **params):
        return DatabaseNamespaceManager(namespace, url, **params)
    create_namespace = classmethod(create_namespace)

    def lock_createfunc(self, wait = True):
        if self.funclock is None:
            self.funclock = Synchronizer(identifier =
"databasecontainer/funclock/%s" % self.namespacemanager.namespace,
use_files = True, lock_dir = self.namespacemanager.lock_dir)

        return self.funclock.acquire_write_lock(wait)

    def unlock_createfunc(self):
        self.funclock.release_write_lock()
