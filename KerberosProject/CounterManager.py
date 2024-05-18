import Constants


class CounterManager():
    def __init__(self):
        self.device_ticket_counter_dict = dict()
        self.device_attestation_time_dict = dict()
        self.device_challange_dict = dict()
        self.device_reset_counter_dict = dict()
        for device_id_name in Constants.device_ids:
            actual_device_id = Constants.device_id_dict[device_id_name]
            self.device_ticket_counter_dict[actual_device_id]=0