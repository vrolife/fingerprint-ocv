/*
Copyright (C) 2022  pom@vro.life

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef __cvext_hpp__
#define __cvext_hpp__

#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>

namespace cvext {

template<typename T>
void gamma(const cv::Mat& input, cv::Mat& output, double gamma)
{
    for (size_t row = 0; row < input.rows; ++row) {
        for (size_t col = 0; col < input.cols; ++col) {
            auto val = static_cast<double>(input.at<T>(row, col)) / 255;
            val = ::pow(static_cast<double>(val), gamma);
            output.at<T>(row, col) = static_cast<T>(val * 255);
        }
    }
}

bool merge(const cv::Mat& img1, const cv::Mat& mask1, const cv::Mat& img2, cv::Mat& output, cv::Mat& output_mask);

bool match(const cv::Mat& fingerprint, const cv::Mat& fp_mask, const cv::Mat& partial, int min_match, double min_score, bool filter);

}

#endif
