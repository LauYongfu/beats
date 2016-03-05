from packetbeat import BaseTest

#Fails with
#
#Traceback (most recent call last):
#  File "/Users/salyh/sources/go/src/github.com/elastic/beats/packetbeat/tests/system/test_0070_drda_simple.py", line 12, in test_simple
#    objs = self.read_output()
#  File "/Users/salyh/sources/go/src/github.com/elastic/beats/packetbeat/tests/system/packetbeat.py", line 110, in read_output
#    self.all_fields_are_expected(jsons, self.expected_fields)
#  File "../../../libbeat/tests/system/beat/beat.py", line 341, in all_fields_are_expected
#    .format(key))
#Exception: Unexpected key 'requests.EXCSAT.length' found

class Test(BaseTest):

    def test_simple(self):        
        self.render_config_template(
            drda_ports=[1527],
        )
        
        self.run_packetbeat(pcap="drda/drda_simple.pcap", debug_selectors=["*"])
        objs = self.read_output()

        assert len(objs) == 2
