#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cstdio>
#include <fstream>
#include <iostream>

#include <opencv2/core.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>

#include <jinx/logging.hpp>

#include "cvext.hpp"

std::vector<unsigned char> load_data(const std::string& data_path)
{
    struct stat fst{};
    jinx_check_errno(
        ::stat(data_path.c_str(), &fst)
    );

    std::vector<unsigned char> buf{};
    buf.resize(fst.st_size);

    FILE* file = ::fopen(data_path.c_str(), "rb");
    fread(buf.data(), fst.st_size, 1, file);
    ::fclose(file);

    return buf;
}

cv::Mat load_data_and_proc(const std::string& file)
{
    auto fpc_data = load_data(file);
    
    cv::Mat raw{cv::Size{112, 88}, CV_8UC1};
    memcpy(raw.data, fpc_data.data() + 12, fpc_data.size() - 12);

    cv::Mat eqh{cv::Size{112, 88}, CV_8UC1};
    cv::equalizeHist(raw, eqh);

    cv::Mat gam{cv::Size(112, 88), CV_8UC1};
    cvext::gamma<unsigned char>(eqh, gam, 1.5);

    cv::Mat img{cv::Size(224, 176), CV_8UC1};
    cv::resize(gam, img, {224, 176});
    return img;
}

int main(int argc, const char* argv[])
{
    /*
        SIFT
        BFMatcher
        findHomography
        warpPerspective
        gabor_filter
    */

    cv::Mat img1{};
    cv::Mat mask1{};

    {
        img1 = load_data_and_proc("0.data");
        mask1.create(img1.size(), CV_32F);
        mask1.setTo(1.0F);
    }

    // {
    //     auto img2 = load_data_and_proc("3.data");

    //     cv::Mat output{};
    //     cv::Mat mask{};
    //     auto ret = cvext::merge(img1, mask1, img2, output, mask);
    //     if (not ret) {
    //         jinx_error() << "not match\n";
    //         return -1;
    //     }
    //     img1 = std::move(output);
    //     mask1 = std::move(mask);
    // }

    // {
    //     auto img2 = load_data_and_proc("1.data");

    //     cv::Mat output{};
    //     cv::Mat mask{};
    //     auto ret = cvext::merge(img1, mask1, img2, output, mask);
    //     if (not ret) {
    //         jinx_error() << "not match\n";
    //         return -1;
    //     }
    //     img1 = std::move(output);
    //     mask1 = std::move(mask);
    // }

    // {
    //     auto img2 = load_data_and_proc("2.data");

    //     cv::Mat output{};
    //     cv::Mat mask{};
    //     auto ret = cvext::merge(img1, mask1, img2, output, mask);
    //     if (not ret) {
    //         jinx_error() << "not match\n";
    //         return -1;
    //     }
    //     img1 = std::move(output);
    //     mask1 = std::move(mask);
    // }

    {
        auto img2 = load_data_and_proc("3.data");
        auto match = cvext::match(img1, mask1, img2, 10, 0.6);
        std::cout << "score: " << match << std::endl;
    }

    // auto img1_gb = cvext::garbor_filter_block_wise(img1, 32, 24);
    // cv::namedWindow("garbor block", cv::WINDOW_NORMAL);
    // cv::imshow("garbor block", img1_gb);

    // cv::Mat bin{};
    // cv::threshold(img1_gb, bin, 0, 255, cv::THRESH_BINARY | cv::THRESH_OTSU);
    // cv::namedWindow("bin", cv::WINDOW_NORMAL);
    // cv::imshow("bin", bin);

    // cv::namedWindow("img1", cv::WINDOW_NORMAL);
    // cv::imshow("img1", img1);

    cv::waitKey();
    return 0;
}
