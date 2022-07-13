//
// Created by Administrator on 2022/7/13.
//
#include "output.h"
#include "tools/rdkafkacpp.h"

#ifndef KELLECT_KAFKAOUTPUT_H
#define KELLECT_KAFKAOUTPUT_H

#endif //KELLECT_KAFKAOUTPUT_H

static bool run = true;

class my_event_cb : public RdKafka::EventCb {
public:
    void event_cb(RdKafka::Event &event) override {
        switch (event.type())
        {
            case RdKafka::Event::EVENT_ERROR:
                std::cerr << "ERROR (" << RdKafka::err2str(event.err()) << "): " <<
                          event.str() << std::endl;
                if (event.err() == RdKafka::ERR__ALL_BROKERS_DOWN)
                    run = false;
                break;

            case RdKafka::Event::EVENT_STATS:
                std::cerr << "\"STATS\": " << event.str() << std::endl;
                break;

            case RdKafka::Event::EVENT_LOG:
                fprintf(stderr, "LOG-%i-%s: %s\n",
                        event.severity(), event.fac().c_str(), event.str().c_str());
                break;

            default:
                std::cerr << "EVENT " << event.type() <<
                          " (" << RdKafka::err2str(event.err()) << "): " <<
                          event.str() << std::endl;
                break;
        }
    }
};

class my_delivery_report_cb : public RdKafka::DeliveryReportCb {
public:
    void dr_cb(RdKafka::Message& message) override {
        printf("message delivery %d bytes, error:%s, key: %s\n",
               (int32_t)message.len(), message.errstr().c_str(), message.key() ? message.key()->c_str() : "");
    }
};

class my_hash_partitioner_cb : public RdKafka::PartitionerCb {
public:
    int32_t partitioner_cb(const RdKafka::Topic *topic, const std::string *key,
                           int32_t partition_cnt, void *msg_opaque) override {
        return djb_hash(key->c_str(), key->size()) % partition_cnt;
    }
private:
    static inline unsigned int djb_hash(const char *str, size_t len) {
        unsigned int hash = 5381;
        for (size_t i = 0; i < len; i++)
            hash = ((hash << 5) + hash) + str[i];
        return hash;
    }
};

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

    void dump_config(RdKafka::Conf* conf) {
        std::list<std::string> *dump = conf->dump();

        printf("config dump(%d):\n", (int32_t)dump->size());
        for (auto it = dump->begin(); it != dump->end();) {
            std::string name = *it++;
            std::string value = *it++;
            printf("%s = %s\n", name.c_str(), value.c_str());
        }

        printf("---------------------------------------------\n");
    }

private:
    RdKafka::Producer* producer = nullptr;
    RdKafka::Conf* global_conf = nullptr;

    my_event_cb event_cb;
    my_delivery_report_cb   delivery_cb;
    std::string brokers_;
    std::string topics_;
//    std::string groupid_;

    int64_t last_offset_ = 0;
//    RdKafka::Consumer *kafka_consumer_ = nullptr;
//    RdKafka::Topic    *topic_ = nullptr;
    int64_t           offset_ = RdKafka::Topic::OFFSET_BEGINNING;
    int32_t           partition_ = 0;
};
