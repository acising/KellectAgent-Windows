//
// Created by Administrator on 2022/7/13.
//
#include "output/KafkaOutput.h"

int KafkaOutPut::init() {

    STATUS status = parseIPAndPort();
    if (status == STATUS_SUCCESS) {

        brokers_ = ip+":"+ std::to_string(port);
        // create global config instance
        global_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

        // set error message
        std::string errMsg = "";

        // set cluster
        if (global_conf->set("bootstrap.servers", brokers_, errMsg) !=
            RdKafka::Conf::CONF_OK) {
            std::cout << errMsg << std::endl;

            return STATUS_FAIL;
        }

//    global_conf->set("event_cb", &event_cb, errMsg);
//    global_conf->set("dr_cb", &delivery_cb, errMsg);

        // create producer instance
        producer = RdKafka::Producer::create(global_conf, errMsg);
        if (!producer) {
            std::cerr << "Failed to create producer: " << errMsg << std::endl;
            return STATUS_FAIL;
        }

        printf("created kafka producer %s\n", producer->name().c_str());
        delete global_conf;
    }
    if(status == STATUS_SUCCESS)
        setInit(true);
    else
        status = STATUS_KAFKA_FORMAT_ERROR;

    return status;
}

void KafkaOutPut::output(std::string outputString){

    if (outputString.empty()) {
        producer->poll(0);
        return;
//        continue;
    }

    retry:
    // 生产者根据主题发布信息
    RdKafka::ErrorCode err = producer->produce(
            // 主题
            topics_,
            //任何分区：内置分区器将
            //用于将消息分配给基于主题的在消息键上，或没有设定密钥
            RdKafka::Topic::PARTITION_UA,
            // 创建副本？
            RdKafka::Producer::RK_MSG_COPY,
            // 值
            const_cast<char*>(outputString.c_str()), outputString.size(),
            // 键
            NULL, 0,
            // 投递时间，默认当前时间
            0,
            // 消息头
            NULL,
            NULL);

    if (err != RdKafka::ERR_NO_ERROR) {
        std::cerr << "% produce failed " << topics_ << ": "
                  << RdKafka::err2str(err) << std::endl;
        if (err == RdKafka::ERR__QUEUE_FULL) {
            // queue is full, wait for ten seconds to retry
            producer->poll(1000);
            goto retry;
        }
    }
    else {
//        std::cerr << "% produced events, bytes:"<< outputString.size()<< " "<< " topic:"<< topics_<< std::endl;
    }

    producer->poll(0);
}
