import unittest, threading, time
from unittest.mock import patch
from vpn_desk.checker import run_tcp_checks

class CheckerTests(unittest.TestCase):
    def test_bounded_checker_collects_results_and_progress(self):
        rows=[{'id':i,'host':'example.invalid','port':443} for i in range(7)]
        progress=[]
        with patch('vpn_desk.checker.check_tcp',return_value=('reachable',12.0,'')):
            result=run_tcp_checks(rows,max_workers=2,progress=lambda n,total,last:progress.append((n,total)))
        self.assertEqual(len(result),7)
        self.assertEqual(progress[-1],(7,7))


    def test_cancel_returns_partial_results(self):
        rows=[{'id':i,'host':'example.invalid','port':443} for i in range(100)]
        cancel=threading.Event()
        def slow_check(host,port,timeout):
            time.sleep(0.03)
            return 'reachable',10.0,''
        def progress(current,total,last):
            if current>=1:cancel.set()
        with patch('vpn_desk.checker.check_tcp',side_effect=slow_check):
            with self.assertRaises(Exception) as ctx:
                run_tcp_checks(rows,max_workers=2,cancel_event=cancel,progress=progress)
        self.assertGreaterEqual(len(ctx.exception.results),1)

if __name__=='__main__':unittest.main()
