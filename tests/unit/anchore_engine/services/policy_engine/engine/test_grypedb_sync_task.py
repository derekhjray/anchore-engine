import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, Mock

import pytest

from anchore_engine.db import GrypeDBMetadata
from anchore_engine.services.policy_engine.engine.tasks import (
    GrypeDBSyncTask,
    TooManyActiveGrypeDBs,
)


class TestGrypeDBSyncTask:
    @pytest.fixture
    def mock_query_active_dbs_with_data(self):
        """
        Creates factory that will mock _query_active_dbs return with params passed
        """

        def _mock_query(mocked_output):
            mock_active_dbs = Mock(return_value=mocked_output)
            GrypeDBSyncTask._query_active_dbs = mock_active_dbs

        return _mock_query

    @pytest.fixture
    def mock_get_local_grypedb_checksum(self):
        """
        Creates factory that will mock _query_active_dbs return with params passed
        """

        def _mock_query(mocked_output):
            mock_checksum = Mock(return_value=mocked_output)
            GrypeDBSyncTask.get_local_grypedb_checksum = mock_checksum

        return _mock_query

    @pytest.fixture
    def mock_calls_for_sync(
        self, mock_query_active_dbs_with_data, mock_get_local_grypedb_checksum
    ):
        """
        Provides ability to mock all class methods necessary to run a sync as a unit test
        """

        def _mock(mock_active_dbs=[], mock_local_checksum=""):
            mock_query_active_dbs_with_data(mock_active_dbs)
            mock_get_local_grypedb_checksum(mock_local_checksum)

        return _mock

    def test_no_active_grypedb(self, mock_calls_for_sync):
        mock_calls_for_sync(
            mock_active_dbs=[],
            mock_local_checksum="eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c",
        )
        result = GrypeDBSyncTask.run_grypedb_sync()

        assert not result

    def test_too_many_active_grypedbs(self, mock_query_active_dbs_with_data):
        active_dbs = [GrypeDBMetadata(active=True), GrypeDBMetadata(active=True)]
        mock_query_active_dbs_with_data(active_dbs)

        with pytest.raises(TooManyActiveGrypeDBs):
            GrypeDBSyncTask.run_grypedb_sync()

    def test_matching_checksums(self, mock_calls_for_sync):
        checksum = "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c"
        mock_calls_for_sync(
            mock_active_dbs=[GrypeDBMetadata(checksum=checksum)],
            mock_local_checksum=checksum,
        )

        sync_ran = GrypeDBSyncTask.run_grypedb_sync()

        assert not sync_ran

    def test_mismatch_checksum(self, mock_calls_for_sync):
        global_checksum = (
            "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c"
        )
        local_checksum = (
            "366ab0a94f4ed9c22f5cc93e4d8f6724163a357ae5190740c1b5f251fd706cc4"
        )

        mock_calls_for_sync(
            mock_active_dbs=[GrypeDBMetadata(checksum=global_checksum)],
            mock_local_checksum=local_checksum,
        )

        # pass a file path to bypass connection to catalog to retrieve tar from object storage
        sync_ran = GrypeDBSyncTask.run_grypedb_sync(
            grypedb_file_path="test/bypass/catalog.txt"
        )

        assert sync_ran

    def test_class_lock_called(self, mock_calls_for_sync):
        """
        Verfies that the lock enter and exit methods are called to ensure that the lock is being used correctly
        Verifies on matching checksum in order to assert the lock is called even when the task is not executed
        """
        checksum = "366ab0a94f4ed9c22f5cc93e4d8f6724163a357ae5190740c1b5f251fd706cc4"
        mock_lock = MagicMock()
        GrypeDBSyncTask.lock = mock_lock
        mock_calls_for_sync(
            mock_active_dbs=[GrypeDBMetadata(checksum=checksum)],
            mock_local_checksum=checksum,
        )

        sync_ran = GrypeDBSyncTask.run_grypedb_sync(
            grypedb_file_path="test/bypass/catalog.txt"
        )

        assert not sync_ran
        assert mock_lock.__enter__.called
        assert mock_lock.__exit__.called

    def test_lock_across_threads(self, mock_calls_for_sync):
        """
        Verifies the output of the tasks when designed to ensure that one thread hits the lock before the other finishes

        Runs 2 tasks: creates thread that runs sync task and then another task is run synchronously (synchronous_task)
        Mocks the execute function to wait 5 seconds to ensure race condition with thread1 and synchronous_task
        The mock also updates active and local grype dbs to mimic real behavior
        Run thread1 and once the lock is taken, it runs synchronous_task, which is identical to thread1
        If lock correctly blocks synchronous_task from evaluating, only thread1 should run the execute method
        """
        old_checksum = (
            "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c"
        )
        new_checksum = (
            "366ab0a94f4ed9c22f5cc93e4d8f6724163a357ae5190740c1b5f251fd706cc4"
        )

        # mock initial state so execution occurs
        mock_calls_for_sync([GrypeDBMetadata(checksum=old_checksum)], "")

        # Mock the execute method for task to sleep and update mocks for active and local grype dbs
        def _mock_execute_for_thread1(instance):
            # sleep to ensure lock is taken
            time.sleep(5)

            # mock the returns to mimic persistent change of active grypedb local and global
            # This in effect mocks the actual execution for the first thread
            mock_calls_for_sync([GrypeDBMetadata(checksum=new_checksum)], new_checksum)

        GrypeDBSyncTask.execute = _mock_execute_for_thread1

        with ThreadPoolExecutor() as executor:
            # run thread1
            thread1 = executor.submit(
                GrypeDBSyncTask.run_grypedb_sync, "test/bypass/catalog.txt"
            )

        # Wait until thread1 has taken the lock and then run thread2 with timeout of ~5 seconds
        synchronous_task = False
        for attempt in range(5):
            if GrypeDBSyncTask.lock.locked():
                synchronous_task = GrypeDBSyncTask.run_grypedb_sync(
                    grypedb_file_path="test/bypass/catalog.txt"
                )
            else:
                time.sleep(1)

        assert thread1.result() == True
        assert synchronous_task == False