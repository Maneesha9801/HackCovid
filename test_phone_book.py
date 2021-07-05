import contextlib
import subprocess
import os


import pytest

@pytest.fixture
def no_db():
    with contextlib.suppress(Exception):
        os.unlink("directory.db")

def run_cmd(cmd):
    cmd = cmd.split()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ret = p.wait()
    return ret, p.stdout.read().decode("ascii").strip()


def test_list_without_db(no_db):
    exit_status, op = run_cmd("./phone_book list")
    assert exit_status == 1
    assert op == "Couldn't open database file: No such file or directory"

def test_search_without_db(no_db):
    exit_status, op = run_cmd("./phone_book search foo")
    assert exit_status == 1
    assert op == "Couldn't open database file: No such file or directory"

def test_delete_without_db(no_db):
    exit_status, op = run_cmd("./phone_book delete foo")
    assert exit_status == 1
    assert op == "Couldn't open database file: No such file or directory"

def test_adding_listing(no_db):
    exit_status, _ = run_cmd("./phone_book add john 1234567890")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add jack 0987654321")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add james 5432167890")
    assert exit_status == 0

    exit_status, op = run_cmd("./phone_book list")
    assert exit_status == 0
    expected = """john                 : 1234567890
jack                 : 0987654321
james                : 5432167890
Total entries :  3"""
    assert (op == expected)

def test_adding_searching_found(no_db):
    exit_status, _ = run_cmd("./phone_book add john 1234567890")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add jack 0987654321")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add james 5432167890")
    assert exit_status == 0

    exit_status, op = run_cmd("./phone_book search john")
    assert exit_status == 0
    expected = "1234567890"
    assert (op == expected)

def test_adding_searching_notfound(no_db):
    exit_status, _ = run_cmd("./phone_book add john 1234567890")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add jack 0987654321")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add james 5432167890")
    assert exit_status == 0

    exit_status, op = run_cmd("./phone_book search wick")
    assert exit_status == 1
    expected = "no match"
    assert (op == expected)

def test_adding_deleting_nonexistent(no_db):
    exit_status, _ = run_cmd("./phone_book add john 1234567890")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add jack 0987654321")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add james 5432167890")
    assert exit_status == 0

    exit_status, op = run_cmd("./phone_book delete wick")
    assert exit_status == 1
    expected = "no match"
    assert (op == expected)

def test_adding_deleting_first_list(no_db):
    exit_status, _ = run_cmd("./phone_book add john 1234567890")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add jack 0987654321")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add james 5432167890")
    assert exit_status == 0

    exit_status, op = run_cmd("./phone_book delete john")
    assert exit_status == 0
    exit_status, op = run_cmd("./phone_book list")
    assert exit_status == 0
    expected = """jack                 : 0987654321
james                : 5432167890
Total entries :  2"""
    assert (op == expected)
    
def test_adding_deleting_middle_list(no_db):
    exit_status, _ = run_cmd("./phone_book add john 1234567890")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add jack 0987654321")
    assert exit_status == 0
    exit_status, _ = run_cmd("./phone_book add james 5432167890")
    assert exit_status == 0

    exit_status, op = run_cmd("./phone_book delete jack")
    assert exit_status == 0
    exit_status, op = run_cmd("./phone_book list")
    assert exit_status == 0
    expected = """john                 : 1234567890
james                : 5432167890
Total entries :  2"""
    assert (op == expected)

    
def test_valgrind(no_db):
    run_cmd("./phone_book add john 1234567890")
    run_cmd("./phone_book add jack 0987654321")
    run_cmd("./phone_book add james 5432167890")

    exit_status, op = run_cmd("valgrind ./phone_book list")
    assert "All heap blocks were freed -- no leaks are possible" in op, "Memory is not being properly freed"
    
    
    
