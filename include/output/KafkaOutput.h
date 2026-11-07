//
// Created by Administrator on 2022/7/13.
//
#include "output.h"
#include "tools/rdkafkacpp.h"

#ifndef KELLECT_KAFKAOUTPUT_H
#define KELLECT_KAFKAOUTPUT_H

#endif //KELLECT_KAFKAOUTPUT_H

class KafkaOutPut : public Output {

public:
    virtual void output(std::string outputString) override;
    virtual STATUS init() override;

    KafkaOutPut(std::string ip_port,std::string topic){
        this->ip_port = ip_port;
//        this->brokers_ = brokers;
        this->topics_ = topic;
    }

    ~KafkaOutPut();

private:
    RdKafka::Producer* producer = nullptr;

    std::string brokers_;
    std::string topics_;
//    std::string groupid_;

    int64_t last_offset_ = 0;
//    RdKafka::Consumer *kafka_consumer_ = nullptr;
//    RdKafka::Topic    *topic_ = nullptr;
    int64_t           offset_ = RdKafka::Topic::OFFSET_BEGINNING;
    int32_t           partition_ = 0;
};
