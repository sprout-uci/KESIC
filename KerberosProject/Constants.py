usernames = ['user1', 'user2']
service_ids = ["iot_service"]
device_ids = ["smart_bulb0", "smart_bulb1"]
device_ticket_validity_in_seconds=300
allowed_commands = ['turn_on', 'turn_off', 'attest']
command_dict={
    "turn_on": "01",
    "turn_off": "00",
    "attest": "11"
}
client_id_dict={
    "user1":"00000001",
    "user2":"00000002"
}
client_interface_dict={
    "user1":"00000001",
    "user2":"00000001"
}
device_id_dict={
    "smart_bulb0":"00000001",
    "smart_bulb1":"00000002"
}
iot_device_key1_dict={
    "00000001":"10129F4621B479E84D0D168823F1A2D4DC85525AE879E5860273916B91C724E9",
    "00000002":"10129F4621B479E84D0D168823F1A2D4DC85525AE879E5860273916B91C724E9"
}
iot_device_key2_dict={
    "00000001":"10129FE84D0D168823F1A2D4DC85525AE879E5864621B4790273916B91C724E9",
    "00000002":"10129FE84D0D168823F1A2D4DC85525AE879E5864621B4790273916B91C724E9"
}
iot_device_key3_dict={
    "00000001":"10129F91C724E94621B479E84D0D168823F1A2D4DC85525AE879E5860273916B",
    "00000002":"10129F91C724E94621B479E84D0D168823F1A2D4DC85525AE879E5860273916B"
}
device_type_normal = "normal"
device_type_nordic = "nordic"
iot_device_type_dict = {
    "00000001":device_type_normal,
    "00000002":device_type_nordic
}
iot_device_memory_dict = {
    "00000001":"27E08DED415EA56D781219F63863C955C52933AC881552DA477A307ABD1013BD",
    "00000002":"27E08DED415EA56D781219F63863C955C52933AC881552DA477A307ABD1013BD"
}
# Actual values would be around 15 seconds. However, a larger value is put here to compensate for human speed
iot_device_awake_time_dict={
    "00000002": 60.0
}
service_id_dict={
    "iot_service":"10110010"
}

device_ticket_info_format = "{0}{1}{2}{3}"
normal_device_request_format = "{0}{1}{2}{3}{4}{5}{6}"
nordic_device_request_format = "{0}{1}{2}{3}{4}"
boot_sync_response_format = "{0}{1}{2}{3}"
boot_sync_response_plaintext_format = "{0}{1}{2}"