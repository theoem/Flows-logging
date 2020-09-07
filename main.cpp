#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cmath>
#include <chrono>
#include <string>
#include <fstream>
#include <map>
#include <ctime>
#include <unistd.h>
#include <pqxx/pqxx>
#include <thread>

#include "libtrace.h"
#include "libflowmanager.h"
#include "libprotoident.h"

FlowManager *fm = NULL;

bool let_rfc1918 = true;
std::string conn_str;

struct flow_info {
    int count;
    int time;
};

typedef struct counter {
    uint64_t packets;
    lpi_data_t lpi;
    double start_ts;
    double end_ts;
} CounterFlow;

void init_counter_flow(Flow *f, double ts) {
    CounterFlow *cflow = NULL;

    cflow = (CounterFlow *) malloc(sizeof(CounterFlow));
    cflow->packets = 0;
    cflow->start_ts = ts;
    cflow->end_ts = ts;

    lpi_init_data(&cflow->lpi);
    f->extension = cflow;
}


void expire_counter_flows(double ts, bool exp_flag) {
    Flow *expired;

    // Loop until libflowmanager has no more expired flows available
    if ((expired = fm->expireNextFlow(ts, exp_flag)) != NULL) {
        //start transaction with database
        pqxx::connection c{conn_str};
        pqxx::work txn{c};

        c.prepare(
                "statement",
                "INSERT INTO flows1(time, src_ip, src_port, dst_ip, dst_port, protocol, duration)"
                "VALUES ($1, $2, $3, $4, $5, $6, $7);");

        do {
            CounterFlow *cflow = (CounterFlow *) expired->extension;

            //display flow
            char src_ip[100];
            char dst_ip[100];
            double duration;
            std::string src_port;
            std::string dst_port;
            lpi_module_t *proto;

            proto = lpi_guess_protocol(&cflow->lpi);
            expired->id.get_server_ip_str(src_ip);
            expired->id.get_client_ip_str(dst_ip);


            src_port = std::to_string(expired->id.get_server_port());
            dst_port = std::to_string(expired->id.get_client_port());
            duration = cflow->end_ts - cflow->start_ts;


            txn.exec_prepared("statement", lround(cflow->start_ts), src_ip, src_port, dst_ip,
                              dst_port, proto->name, round(duration * 100.0) / 100.0);

            //release flow
            free(cflow);
            fm->releaseFlow(expired);
        } while ((expired = fm->expireNextFlow(ts, exp_flag)) != NULL);

        txn.commit();
        std::cout << "flows1 data flushed to databse" << std::endl;
    }
}

void per_packet(libtrace_packet_t *packet) {
    Flow *f;
    CounterFlow *cflow = NULL;
    uint8_t dir;
    bool is_new = false;

    libtrace_ip_t *ip = NULL;
    double ts;

    uint16_t l3_type;

    // Libflowmanager only deals with IP traffic, so ignore anything
    // that does not have an IP header
    ip = (libtrace_ip_t *) trace_get_layer3(packet, &l3_type, NULL);
    if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) {
        return;
    }

    if (ip == NULL) return;

    ts = trace_get_seconds(packet);

    // get direction using trace_get_direction() is not ideal
    if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
        dir = 0;
    else
        dir = 1;

    // Ignore packets where the IP addresses are the same - something is
    // probably screwy and it's REALLY hard to determine direction
    if (ip->ip_src.s_addr == ip->ip_dst.s_addr)
        return;

    f = fm->matchPacketToFlow(packet, dir, &is_new);

    if (f == NULL)
        return;

    if (is_new) {
        init_counter_flow(f, ts);
        cflow = (CounterFlow *) f->extension;
    } else {
        cflow = (CounterFlow *) f->extension;
        if (cflow->end_ts < ts)
            cflow->end_ts = ts;
    }

    cflow->packets++;

    lpi_update_data(packet, &cflow->lpi, dir);
    fm->updateFlowExpiry(f, packet, dir, ts);

}

int flows_main(char *path) {
    libtrace_t *trace;
    libtrace_packet_t *packet;

    double ts;
    lfm_plugin_id_t plugid = LFM_PLUGIN_STANDARD;


    packet = trace_create_packet();
    if (packet == NULL) {
        perror("Creating libtrace packet");
        return -1;
    }

    fm = new FlowManager();

    // This tells libflowmanager to ignore any flows where an RFC1918
    // private IP address is involved
    if (fm->setConfigOption(LFM_CONFIG_IGNORE_RFC1918, &let_rfc1918) == 0)
        return -1;


    if (fm->setConfigOption(LFM_CONFIG_EXPIRY_PLUGIN, &plugid) == 0)
        return -1;

    if (lpi_init_library() == -1)
        return -1;

    if (strlen(path) != 0) {
        printf("flows1 URI: %s\n", path);

        // Bog-standard libtrace stuff for reading trace files
        trace = trace_create(path);

        if (!trace) {
            perror("Creating libtrace trace");
            return -1;
        }

        if (trace_is_err(trace)) {
            trace_perror(trace, "Opening trace file");
            trace_destroy(trace);
        }

        if (trace_start(trace) == -1) {
            trace_perror(trace, "Starting trace");
            trace_destroy(trace);
        }
        //start benchmarking
        auto start = std::chrono::high_resolution_clock::now();
        long p_count = 0;
        while (trace_read_packet(trace, packet) > 0) {

            ts = trace_get_seconds(packet);
            per_packet(packet);

            p_count++;

            auto now = std::chrono::high_resolution_clock::now();

            if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() > 120) {
                expire_counter_flows(ts, false);
                start = std::chrono::high_resolution_clock::now();
            }
        }
        //stop benchmarking
        auto stop = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
        std::ofstream benchfile("benchmarking.txt", std::ios_base::app);
        benchfile << "flow1 packets:microseconds: " << p_count << ":" << duration << std::endl;
        benchfile << "flow1 pps: " << (p_count / (double) duration) * 1000000 << std::endl;
        benchfile.close();

        std::cout << "finished reading flows1 packets" << std::endl;

        if (trace_is_err(trace)) {
            trace_perror(trace, "Reading packets");
            trace_destroy(trace);
        }

        trace_destroy(trace);
    }

    trace_destroy_packet(packet);
    expire_counter_flows(0, true);
    delete (fm);

    return -1;
}

void analysis_expire(std::map <std::string, flow_info> &flows, int sleep) {
    bool flush = false;

    std::cout << "flows2 flows in memory:" << flows.size() << std::endl;

    pqxx::connection c{conn_str};
    pqxx::work txn{c};

    c.prepare(
            "statement2",
            "INSERT INTO flows2(time, src_ip, dst_port, count) "
            "VALUES ($1, $2, $3, $4);");

    for (auto it = flows.cbegin(); it != flows.cend();) {
        if (std::time(0) - it->second.time >= sleep) {
            txn.exec_prepared("statement2", it->second.time, it->first.substr(0, it->first.find(':')),
                              it->first.substr(it->first.find(':') + 1), it->second.count);

            it = flows.erase(it);
            flush = true;
        } else ++it;
    }
    txn.commit();
    if (flush) std::cout << "flows2 data flushed to databse" << std::endl;
}

void analysis(const char *path, std::map <std::string, flow_info> &flows, int sleep) {

    char offset_file[] = "line.txt";
    int offset = 1;

    std::ifstream o_stream(offset_file);
    o_stream >> offset;

    std::ifstream ifs(path);

    if (ifs.is_open()) {
        std::string dummy;
        std::string line;
        std::string port;
        std::string ip;
        bool is_content = false;
        int position_dummy;

        for (int n = 1; n < offset; n++) {
            if (!std::getline(ifs, line)) {
                std::ofstream outfile(offset_file);
                outfile << 0 << std::endl;
                outfile.close();

                std::ifstream ifs(path);
            }
        }

        //start benchmarking
        auto start = std::chrono::high_resolution_clock::now();
        long p_count = 0;

        while (std::getline(ifs, line)) {

            if (line.size() > 1) {
                offset++;
                is_content = true;

                position_dummy = line.find("DPT=");
                if (position_dummy >= 0) {
                    dummy = line.substr(position_dummy);
                    position_dummy = dummy.find(' ');
                    port = dummy.substr(4, position_dummy - 4);
                }

                position_dummy = line.find("SRC=");
                if (position_dummy >= 0) {
                    dummy = line.substr(position_dummy);
                    position_dummy = dummy.find(' ');
                    ip = dummy.substr(4, position_dummy - 4);
                }
                if (port != "" && ip != "") {
                    std::stringstream ss;
                    ss << ip << ":" << port;
                    std::string s = ss.str();

                    flows[s].count += 1;
                    flows[s].time = std::time(0);
                }
                p_count++;
            }
        }

        //stop benchmarking
        auto stop = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
        std::ofstream benchfile("benchmarking.txt", std::ios_base::app);
        benchfile << "flow2 packets:microseconds: " << p_count << ":" << duration << std::endl;
        benchfile << "flow2 pps: " << (p_count / (double) duration) * 1000000 << std::endl;
        benchfile.close();

        std::ofstream outfile(offset_file);
        outfile << offset << std::endl;
        outfile.close();

        if (is_content) std::ifstream ifs(path);

        std::cout << "finished reading flows2 packets" << std::endl;
    }
    analysis_expire(flows, sleep);
}


int analysis_main(char *path) {
    std::map <std::string, flow_info> flows;
    int microseconds = 120000000;
    int seconds = microseconds / 1000000;

    if (strlen(path) != 0) {
        printf("flows2 URI: %s\n", path);
        while (true) {
            analysis(path, flows, seconds);
            usleep(microseconds);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {

    bool help = false;
    int opt;
    char* flow1_path = "";
    char* flow2_path = "";

    while ((opt = getopt(argc, argv, "u:l:rc:h")) != EOF) {
        switch (opt) {
            case 'u':
                flow1_path = optarg;
                break;
            case 'l':
                flow2_path = optarg;
                break;
            case 'r':
                let_rfc1918 = false;
                break;
            case 'c':
                conn_str = optarg;
                break;
            case 'h':
                help = true;
            default:
                printf("Usage details ");
                printf("[-u <inputURI>] [-l <inputLOG>]\n\n");
                printf("Options:\n");
                printf("    -u  <inputURI>  URI to trace that is supported by libtrace for analysing flows1 \n");
                printf("    -r  Don't ignore flows involving private RFC 1918 address "
                       "space for flows1 (Ignored by default)\n");
                printf("    -l  <inputLOG>  URI to LOG file for analysing flows2 \n");
                printf("    -c  <connInfo>  SQL connection info string. Example: "
                       "\"host=localhost dbname=mydb user=postgres password=12345\"");
                exit(0);
        }
    }

    if (!help) {
        if (conn_str.empty()) printf("You must provide connection string -c  <connInfo>");
        else {
            std::thread first(flows_main, flow1_path);
            std::thread second(analysis_main, flow2_path);

            first.join();
            second.join();
        }
    }

    return 0;
}