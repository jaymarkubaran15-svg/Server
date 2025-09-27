-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jul 01, 2025 at 02:09 AM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `memotrace`
--

-- --------------------------------------------------------

--
-- Table structure for table `alumni`
--

CREATE TABLE `alumni` (
  `id` int(11) NOT NULL,
  `first_name` varchar(100) NOT NULL,
  `middle_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `alumni_card_number` varchar(50) NOT NULL,
  `gender` enum('male','female','other') DEFAULT NULL,
  `year_graduate` year(4) NOT NULL,
  `course` varchar(100) NOT NULL,
  `work_title` varchar(100) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `verification_token` varchar(64) DEFAULT NULL,
  `is_verified` tinyint(1) DEFAULT 0,
  `privacy_policy_accepted` tinyint(1) NOT NULL DEFAULT 0,
  `role` enum('alumni','admin') DEFAULT 'alumni',
  `has_submitted_survey` tinyint(1) DEFAULT 0,
  `profile` varchar(255) DEFAULT NULL,
  `verification_code` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `alumni`
--

INSERT INTO `alumni` (`id`, `first_name`, `middle_name`, `last_name`, `email`, `alumni_card_number`, `gender`, `year_graduate`, `course`, `work_title`, `address`, `password`, `created_at`, `verification_token`, `is_verified`, `privacy_policy_accepted`, `role`, `has_submitted_survey`, `profile`, `verification_code`) VALUES
(46, 'Rhodian', 'Degumbis', 'Generalao', 'generalaorhodian0@gmail.com', '00001', 'male', '2004', 'Bachelor of Multimedia Arts', '2D/3D Animator', 'Lower Ipil Heights Ipil Zamboanga Sibugay', '$2b$10$n6DIl5BHnU4Q9QXPjmrs0OsZx/Zc7rKsCZaxXwsW.x08DWxGZhKiG', '2025-06-28 02:51:17', NULL, 1, 1, 'alumni', 1, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `alumni_ids`
--

CREATE TABLE `alumni_ids` (
  `id` int(11) NOT NULL,
  `alumni_id` varchar(20) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `alumni_ids`
--

INSERT INTO `alumni_ids` (`id`, `alumni_id`) VALUES
(193, '00001'),
(194, '00002'),
(195, '00003'),
(196, '00004'),
(197, '00005'),
(198, '00006'),
(199, '00007'),
(200, '00008'),
(201, '00009'),
(202, '00010'),
(203, '00011'),
(204, '00012'),
(205, '00013'),
(206, '00014'),
(207, '00015'),
(208, '00016'),
(209, '00017'),
(210, '00018'),
(211, '00019'),
(212, '00020'),
(213, '00021'),
(214, '00022'),
(215, '00023'),
(216, '00024'),
(217, '00025'),
(218, '00026'),
(219, '00027'),
(220, '00028'),
(221, '00029'),
(222, '00030'),
(102, '151515'),
(101, '20241526');

-- --------------------------------------------------------

--
-- Table structure for table `alumni_survey`
--

CREATE TABLE `alumni_survey` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `middlename` varchar(255) DEFAULT NULL,
  `lastname` varchar(255) NOT NULL,
  `gender` varchar(50) NOT NULL,
  `course` varchar(255) NOT NULL,
  `work` varchar(255) NOT NULL,
  `yeargraduate` int(11) NOT NULL,
  `employment_status` varchar(255) NOT NULL,
  `industry` varchar(255) NOT NULL,
  `work_experience` varchar(255) NOT NULL,
  `education_relevance` varchar(255) NOT NULL,
  `alumni_events` varchar(255) NOT NULL,
  `skills` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`skills`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `alumni_survey`
--

INSERT INTO `alumni_survey` (`id`, `name`, `middlename`, `lastname`, `gender`, `course`, `work`, `yeargraduate`, `employment_status`, `industry`, `work_experience`, `education_relevance`, `alumni_events`, `skills`, `created_at`) VALUES
(1, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'Less than 1 year', 'Somewhat relevant', 'Yes', '{\"Technical skills\":true,\"Problem-solving skills\":true}', '2025-03-15 09:15:43'),
(2, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'Less than 1 year', 'Somewhat relevant', 'Yes', '{\"Technical skills\":true,\"Problem-solving skills\":true}', '2025-03-15 09:36:48'),
(3, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'Less than 1 year', 'Highly relevant', 'Yes', '{\"Technical skills\":true,\"Problem-solving skills\":true}', '2025-03-15 09:43:48'),
(4, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'Less than 1 year', 'Highly relevant', 'Yes', '{\"Technical skills\":true,\"Problem-solving skills\":true}', '2025-03-15 09:52:11'),
(5, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'Less than 1 year', 'Neutral', 'Yes', '{\"Technical skills\":true,\"Problem-solving skills\":true}', '2025-03-15 09:54:59'),
(6, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Part-time)', 'Other', 'More than 10 years', 'Not relevant at all', 'Yes', '{\"Other\":true}', '2025-03-15 10:10:16'),
(7, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'Less than 1 year', 'Highly relevant', 'Yes', '{\"Technical skills\":true}', '2025-03-15 10:37:38'),
(8, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Not seeking employment', 'Education', '7-10 years', 'Highly relevant', 'Yes', '{\"Communication skills\":true,\"Other\":true}', '2025-03-15 14:22:14'),
(9, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Business/Finance', 'More than 10 years', 'Not relevant at all', 'Maybe', '{\"Other\":true}', '2025-04-02 13:37:10'),
(10, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Technology/IT', 'More than 10 years', 'Not relevant at all', 'Maybe', '{\"Leadership and management\":true,\"Communication skills\":true,\"Other\":true}', '2025-04-02 13:42:43'),
(11, 'Jay', 'Duyanan', 'Ubaran', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Technology/IT', '7-10 years', 'Not relevant at all', 'No', '{\"Other\":true}', '2025-04-02 13:42:57'),
(12, 'Jay', 'Duyanan', 'duyanan', 'male', 'Bachelor of Science in Computer Science ', 'Branding Specialist', 2004, 'Employed (Full-time)', 'Technology/IT', 'More than 10 years', 'Slightly relevant', 'Yes', '{\"Leadership and management\":true}', '2025-06-16 13:22:03'),
(13, 'Jay Mark', 'Duyanan', 'Ubaran', 'female', 'Bachelor of Science in Computer Science ', 'AI Developer', 2000, 'Employed (Full-time)', 'Technology/IT', '1-3 years', 'Not relevant at all', 'No', '{\"Communication skills\":true,\"Leadership and management\":true}', '2025-06-24 14:21:50'),
(14, 'Rhodian', 'Degumbis', 'Generalao', '', 'Bachelor of Multimedia Arts', '2D/3D Animator', 2004, 'Unemployed but seeking a job', 'Healthcare', '4-6 years', 'Slightly relevant', 'Yes', '{\"Problem-solving skills\":true}', '2025-06-26 14:39:20'),
(15, 'Rhodian', 'Degumbis', 'Generalao', 'male', 'Bachelor of Multimedia Arts', '2D/3D Animator', 2004, 'Employed (Part-time)', 'Technology/IT', '4-6 years', 'Somewhat relevant', 'Yes', '{\"Technical skills\":true}', '2025-06-26 14:58:40'),
(16, 'Rhodian', 'Degumbis', 'Generalao', 'male', 'Bachelor of Multimedia Arts', '2D/3D Animator', 2004, 'Employed (Part-time)', 'Government', 'More than 10 years', 'Not relevant at all', 'No', '{\"Problem-solving skills\":true,\"Leadership and management\":true}', '2025-06-28 04:57:42'),
(17, 'Rhodian', 'Degumbis', 'Generalao', 'male', 'Bachelor of Multimedia Arts', '2D/3D Animator', 2004, 'Employed (Part-time)', 'Government', 'More than 10 years', 'Not relevant at all', 'No', '{\"Problem-solving skills\":true,\"Leadership and management\":true}', '2025-06-28 04:57:45');

-- --------------------------------------------------------

--
-- Table structure for table `courses`
--

CREATE TABLE `courses` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `courses`
--

INSERT INTO `courses` (`id`, `name`) VALUES
(32, 'Bachelor of Multimedia Arts'),
(33, 'Bachelor of Science in Computer Science '),
(31, 'Bachelor of Science in Social work '),
(34, 'Bs');

-- --------------------------------------------------------

--
-- Table structure for table `email_verifications`
--

CREATE TABLE `email_verifications` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `email` varchar(255) NOT NULL,
  `code` varchar(10) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `events`
--

CREATE TABLE `events` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content` text NOT NULL,
  `location_name` varchar(255) DEFAULT NULL,
  `latitude` decimal(10,8) DEFAULT NULL,
  `longitude` decimal(11,8) DEFAULT NULL,
  `images` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `images`
--

CREATE TABLE `images` (
  `id` int(11) NOT NULL,
  `yearbook_id` int(11) DEFAULT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_path` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `images`
--

INSERT INTO `images` (`id`, `yearbook_id`, `file_name`, `file_path`) VALUES
(561, 9, '1.jpg', 'uploads\\YearBook 2021\\1.jpg'),
(562, 9, '10.jpg', 'uploads\\YearBook 2021\\10.jpg'),
(563, 9, '11.jpg', 'uploads\\YearBook 2021\\11.jpg'),
(564, 9, '12.jpg', 'uploads\\YearBook 2021\\12.jpg'),
(565, 9, '13.jpg', 'uploads\\YearBook 2021\\13.jpg'),
(566, 9, '14.jpg', 'uploads\\YearBook 2021\\14.jpg'),
(567, 9, '15.jpg', 'uploads\\YearBook 2021\\15.jpg'),
(568, 9, '16.jpg', 'uploads\\YearBook 2021\\16.jpg'),
(569, 9, '17.jpg', 'uploads\\YearBook 2021\\17.jpg'),
(570, 9, '18.jpg', 'uploads\\YearBook 2021\\18.jpg'),
(571, 9, '19.jpg', 'uploads\\YearBook 2021\\19.jpg'),
(572, 9, '2.jpg', 'uploads\\YearBook 2021\\2.jpg'),
(573, 9, '20.jpg', 'uploads\\YearBook 2021\\20.jpg'),
(574, 9, '21.jpg', 'uploads\\YearBook 2021\\21.jpg'),
(575, 9, '22.jpg', 'uploads\\YearBook 2021\\22.jpg'),
(576, 9, '23.jpg', 'uploads\\YearBook 2021\\23.jpg'),
(577, 9, '24.jpg', 'uploads\\YearBook 2021\\24.jpg'),
(578, 9, '25.jpg', 'uploads\\YearBook 2021\\25.jpg'),
(579, 9, '26.jpg', 'uploads\\YearBook 2021\\26.jpg'),
(580, 9, '27.jpg', 'uploads\\YearBook 2021\\27.jpg'),
(581, 9, '28.jpg', 'uploads\\YearBook 2021\\28.jpg'),
(582, 9, '29.jpg', 'uploads\\YearBook 2021\\29.jpg'),
(583, 9, '3.jpg', 'uploads\\YearBook 2021\\3.jpg'),
(584, 9, '30.jpg', 'uploads\\YearBook 2021\\30.jpg'),
(585, 9, '31.jpg', 'uploads\\YearBook 2021\\31.jpg'),
(586, 9, '32.jpg', 'uploads\\YearBook 2021\\32.jpg'),
(587, 9, '33.jpg', 'uploads\\YearBook 2021\\33.jpg'),
(588, 9, '34.jpg', 'uploads\\YearBook 2021\\34.jpg'),
(589, 9, '35.jpg', 'uploads\\YearBook 2021\\35.jpg'),
(590, 9, '36.jpg', 'uploads\\YearBook 2021\\36.jpg'),
(591, 9, '37.jpg', 'uploads\\YearBook 2021\\37.jpg'),
(592, 9, '38.jpg', 'uploads\\YearBook 2021\\38.jpg'),
(593, 9, '39.jpg', 'uploads\\YearBook 2021\\39.jpg'),
(594, 9, '4.jpg', 'uploads\\YearBook 2021\\4.jpg'),
(595, 9, '40.jpg', 'uploads\\YearBook 2021\\40.jpg'),
(596, 9, '41.jpg', 'uploads\\YearBook 2021\\41.jpg'),
(597, 9, '42.jpg', 'uploads\\YearBook 2021\\42.jpg'),
(598, 9, '43.jpg', 'uploads\\YearBook 2021\\43.jpg'),
(599, 9, '44.jpg', 'uploads\\YearBook 2021\\44.jpg'),
(600, 9, '45.jpg', 'uploads\\YearBook 2021\\45.jpg'),
(601, 9, '46.jpg', 'uploads\\YearBook 2021\\46.jpg'),
(602, 9, '47.jpg', 'uploads\\YearBook 2021\\47.jpg'),
(603, 9, '48.jpg', 'uploads\\YearBook 2021\\48.jpg'),
(604, 9, '49.jpg', 'uploads\\YearBook 2021\\49.jpg'),
(605, 9, '5.jpg', 'uploads\\YearBook 2021\\5.jpg'),
(606, 9, '50.jpg', 'uploads\\YearBook 2021\\50.jpg'),
(607, 9, '51.jpg', 'uploads\\YearBook 2021\\51.jpg'),
(608, 9, '52.jpg', 'uploads\\YearBook 2021\\52.jpg'),
(609, 9, '53.jpg', 'uploads\\YearBook 2021\\53.jpg'),
(610, 9, '54.jpg', 'uploads\\YearBook 2021\\54.jpg'),
(611, 9, '55.jpg', 'uploads\\YearBook 2021\\55.jpg'),
(612, 9, '56.jpg', 'uploads\\YearBook 2021\\56.jpg'),
(613, 9, '57.jpg', 'uploads\\YearBook 2021\\57.jpg'),
(614, 9, '58.jpg', 'uploads\\YearBook 2021\\58.jpg'),
(615, 9, '59.jpg', 'uploads\\YearBook 2021\\59.jpg'),
(616, 9, '6.jpg', 'uploads\\YearBook 2021\\6.jpg'),
(617, 9, '60.jpg', 'uploads\\YearBook 2021\\60.jpg'),
(618, 9, '61.jpg', 'uploads\\YearBook 2021\\61.jpg'),
(619, 9, '62.jpg', 'uploads\\YearBook 2021\\62.jpg'),
(620, 9, '63.jpg', 'uploads\\YearBook 2021\\63.jpg'),
(621, 9, '64.jpg', 'uploads\\YearBook 2021\\64.jpg'),
(622, 9, '65.jpg', 'uploads\\YearBook 2021\\65.jpg'),
(623, 9, '66.jpg', 'uploads\\YearBook 2021\\66.jpg'),
(624, 9, '67.jpg', 'uploads\\YearBook 2021\\67.jpg'),
(625, 9, '68.jpg', 'uploads\\YearBook 2021\\68.jpg'),
(626, 9, '69.jpg', 'uploads\\YearBook 2021\\69.jpg'),
(627, 9, '7.jpg', 'uploads\\YearBook 2021\\7.jpg'),
(628, 9, '70.jpg', 'uploads\\YearBook 2021\\70.jpg'),
(629, 9, '8.jpg', 'uploads\\YearBook 2021\\8.jpg'),
(630, 9, '9.jpg', 'uploads\\YearBook 2021\\9.jpg'),
(631, 10, 'B612-2016-11-25-11-56-48.jpg', 'uploads\\pictures\\B612-2016-11-25-11-56-48.jpg'),
(632, 10, 'B612-2016-11-25-11-56-51.jpg', 'uploads\\pictures\\B612-2016-11-25-11-56-51.jpg'),
(633, 10, 'B612-2016-11-25-11-56-53.jpg', 'uploads\\pictures\\B612-2016-11-25-11-56-53.jpg'),
(634, 10, 'B612-2016-11-25-11-56-55.jpg', 'uploads\\pictures\\B612-2016-11-25-11-56-55.jpg'),
(635, 10, 'B612-2016-11-25-11-57-07.jpg', 'uploads\\pictures\\B612-2016-11-25-11-57-07.jpg'),
(636, 10, 'B612-2016-11-25-12-09-19.jpg', 'uploads\\pictures\\B612-2016-11-25-12-09-19.jpg'),
(637, 10, 'B612-2016-11-25-12-09-43.jpg', 'uploads\\pictures\\B612-2016-11-25-12-09-43.jpg'),
(638, 10, 'B612-2016-11-25-12-10-47.jpg', 'uploads\\pictures\\B612-2016-11-25-12-10-47.jpg'),
(639, 10, 'B612-2016-11-25-12-23-15.jpg', 'uploads\\pictures\\B612-2016-11-25-12-23-15.jpg'),
(640, 10, 'B612-2016-11-25-12-23-43.jpg', 'uploads\\pictures\\B612-2016-11-25-12-23-43.jpg'),
(641, 10, 'B612-2016-11-25-12-26-31.jpg', 'uploads\\pictures\\B612-2016-11-25-12-26-31.jpg'),
(642, 10, 'B612-2016-11-25-12-26-34.jpg', 'uploads\\pictures\\B612-2016-11-25-12-26-34.jpg'),
(643, 10, 'B612-2016-11-25-12-26-36.jpg', 'uploads\\pictures\\B612-2016-11-25-12-26-36.jpg'),
(644, 10, 'B612-2016-11-25-12-29-55.jpg', 'uploads\\pictures\\B612-2016-11-25-12-29-55.jpg'),
(645, 10, 'B612-2016-11-25-12-30-00.jpg', 'uploads\\pictures\\B612-2016-11-25-12-30-00.jpg'),
(646, 10, 'B612-2016-11-25-12-30-04.jpg', 'uploads\\pictures\\B612-2016-11-25-12-30-04.jpg'),
(647, 10, 'B612-2016-11-25-12-30-06.jpg', 'uploads\\pictures\\B612-2016-11-25-12-30-06.jpg'),
(648, 10, 'B612-2016-11-25-12-30-47.jpg', 'uploads\\pictures\\B612-2016-11-25-12-30-47.jpg'),
(649, 10, 'B612-2016-11-25-12-30-56.jpg', 'uploads\\pictures\\B612-2016-11-25-12-30-56.jpg'),
(650, 10, 'B612_20161201_093037.jpg', 'uploads\\pictures\\B612_20161201_093037.jpg'),
(651, 10, 'IMG_20161013_094909.jpg', 'uploads\\pictures\\IMG_20161013_094909.jpg'),
(652, 10, 'IMG_20161013_095011.jpg', 'uploads\\pictures\\IMG_20161013_095011.jpg'),
(653, 10, 'IMG_20161013_095021.jpg', 'uploads\\pictures\\IMG_20161013_095021.jpg'),
(654, 10, 'IMG_20161112_131651.jpg', 'uploads\\pictures\\IMG_20161112_131651.jpg'),
(655, 10, 'IMG_20161201_094245.jpg', 'uploads\\pictures\\IMG_20161201_094245.jpg'),
(656, 10, 'IMG_20161201_094248.jpg', 'uploads\\pictures\\IMG_20161201_094248.jpg'),
(657, 10, 'IMG_20161201_094324.jpg', 'uploads\\pictures\\IMG_20161201_094324.jpg'),
(658, 10, 'IMG_20161201_094328.jpg', 'uploads\\pictures\\IMG_20161201_094328.jpg'),
(659, 10, 'IMG_20161201_094345.jpg', 'uploads\\pictures\\IMG_20161201_094345.jpg'),
(660, 10, 'IMG_20161201_094348.jpg', 'uploads\\pictures\\IMG_20161201_094348.jpg'),
(661, 10, 'IMG_20161201_094355.jpg', 'uploads\\pictures\\IMG_20161201_094355.jpg'),
(662, 10, 'IMG_20161201_094357.jpg', 'uploads\\pictures\\IMG_20161201_094357.jpg'),
(663, 10, 'IMG_20161201_094619.jpg', 'uploads\\pictures\\IMG_20161201_094619.jpg'),
(664, 10, 'IMG_20161201_094622.jpg', 'uploads\\pictures\\IMG_20161201_094622.jpg'),
(665, 10, 'IMG_20161201_094629.jpg', 'uploads\\pictures\\IMG_20161201_094629.jpg'),
(666, 10, 'IMG_20161201_094635.jpg', 'uploads\\pictures\\IMG_20161201_094635.jpg'),
(667, 10, 'IMG_20161201_094637.jpg', 'uploads\\pictures\\IMG_20161201_094637.jpg'),
(668, 10, 'IMG_20161201_103228.jpg', 'uploads\\pictures\\IMG_20161201_103228.jpg'),
(669, 10, 'IMG_20161201_103233.jpg', 'uploads\\pictures\\IMG_20161201_103233.jpg'),
(670, 10, 'IMG_20161201_103240.jpg', 'uploads\\pictures\\IMG_20161201_103240.jpg'),
(671, 10, 'IMG_20161201_103251.jpg', 'uploads\\pictures\\IMG_20161201_103251.jpg'),
(672, 10, 'IMG_20161201_103346.jpg', 'uploads\\pictures\\IMG_20161201_103346.jpg'),
(673, 10, 'IMG_20161201_103348.jpg', 'uploads\\pictures\\IMG_20161201_103348.jpg'),
(674, 10, 'IMG_20161201_103350.jpg', 'uploads\\pictures\\IMG_20161201_103350.jpg'),
(675, 10, 'IMG_20161201_105152.jpg', 'uploads\\pictures\\IMG_20161201_105152.jpg'),
(676, 10, 'IMG_20161201_105250.jpg', 'uploads\\pictures\\IMG_20161201_105250.jpg'),
(677, 10, 'IMG_20161201_105318.jpg', 'uploads\\pictures\\IMG_20161201_105318.jpg'),
(678, 10, 'IMG_20161201_105327.jpg', 'uploads\\pictures\\IMG_20161201_105327.jpg'),
(679, 10, 'IMG_20161201_105356.jpg', 'uploads\\pictures\\IMG_20161201_105356.jpg'),
(680, 10, 'IMG_20161201_105359.jpg', 'uploads\\pictures\\IMG_20161201_105359.jpg'),
(681, 10, 'IMG_20161201_105417.jpg', 'uploads\\pictures\\IMG_20161201_105417.jpg'),
(682, 10, 'IMG_20161201_105419.jpg', 'uploads\\pictures\\IMG_20161201_105419.jpg'),
(683, 10, 'IMG_20161201_110256.jpg', 'uploads\\pictures\\IMG_20161201_110256.jpg'),
(684, 10, 'IMG_20161201_110259.jpg', 'uploads\\pictures\\IMG_20161201_110259.jpg'),
(685, 10, 'IMG_20161201_110318.jpg', 'uploads\\pictures\\IMG_20161201_110318.jpg'),
(686, 10, 'IMG_20161201_110327.jpg', 'uploads\\pictures\\IMG_20161201_110327.jpg'),
(687, 10, 'IMG_20161201_110333.jpg', 'uploads\\pictures\\IMG_20161201_110333.jpg'),
(688, 10, 'IMG_20161201_110336.jpg', 'uploads\\pictures\\IMG_20161201_110336.jpg'),
(689, 10, 'IMG_20161201_110658.jpg', 'uploads\\pictures\\IMG_20161201_110658.jpg'),
(690, 10, 'IMG_20161201_110700.jpg', 'uploads\\pictures\\IMG_20161201_110700.jpg');

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `id` int(11) NOT NULL,
  `type` varchar(50) DEFAULT NULL,
  `message` text NOT NULL,
  `related_id` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `notifications`
--

INSERT INTO `notifications` (`id`, `type`, `message`, `related_id`, `user_id`, `created_at`) VALUES
(6, 'post', 'created a new post', 42, 32, '2025-04-23 19:12:31'),
(7, 'event', ' posted a new event.', 18, 28, '2025-04-24 18:21:48'),
(8, 'yearbook', 'A new yearbook \"Yearbook 2025\" was uploaded.', 10, NULL, '2025-04-24 18:35:05'),
(9, 'post', 'created a new JOB POST', 43, 32, '2025-04-24 19:09:35'),
(10, 'post', 'created a new JOB POST', 44, 32, '2025-04-24 19:10:34'),
(11, 'post', 'created a new JOB POST', 45, 32, '2025-04-24 19:13:07'),
(12, 'post', 'created a new JOB POST', 46, 32, '2025-04-24 19:15:18'),
(13, 'post', 'created a new JOB POST', 47, 32, '2025-04-24 20:01:42'),
(14, 'post', 'created a new JOB POST', 48, 32, '2025-04-24 20:02:05'),
(15, 'post', 'created a new JOB POST', 49, 28, '2025-04-24 20:02:35'),
(16, 'post', 'created a new JOB POST', 50, 32, '2025-04-24 20:25:33'),
(17, 'post', 'created a new JOB POST', 51, 32, '2025-04-24 20:25:42'),
(18, 'post', 'created a new JOB POST', 52, 32, '2025-04-26 13:01:16'),
(19, 'post', 'created a new JOB POST', 53, 32, '2025-04-26 13:03:01'),
(20, 'event', ' posted a new EVENT.', 19, 28, '2025-05-03 11:15:30'),
(21, 'post', 'created a new JOB POST', 54, 28, '2025-06-16 21:28:25'),
(22, 'post', 'created a new JOB POST', 55, 46, '2025-06-28 18:47:37');

-- --------------------------------------------------------

--
-- Table structure for table `posts`
--

CREATE TABLE `posts` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content` text NOT NULL,
  `date_posted` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `posts`
--

INSERT INTO `posts` (`id`, `user_id`, `content`, `date_posted`) VALUES
(55, 46, 'fyguyfuf', '2025-06-28 10:47:36');

-- --------------------------------------------------------

--
-- Table structure for table `students`
--

CREATE TABLE `students` (
  `id` int(11) NOT NULL,
  `yearbook_id` int(11) DEFAULT NULL,
  `first_name` varchar(255) DEFAULT NULL,
  `last_name` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `students`
--

INSERT INTO `students` (`id`, `yearbook_id`, `first_name`, `last_name`) VALUES
(41, 9, 'Lina', 'Haynes'),
(42, 9, 'Kason', 'Gibson'),
(43, 9, 'Eden', 'Buck'),
(44, 9, 'Jon', 'Washington'),
(45, 9, 'Valerie', 'Smith'),
(46, 9, 'Liam', 'Curtis'),
(47, 9, 'Alexis', 'Miles'),
(48, 9, 'Jared', 'Jacobson'),
(49, 9, 'Royal', 'Franco'),
(50, 9, 'Gage', 'Hughes'),
(51, 9, 'Samantha', 'Lugo'),
(52, 9, 'Santos', 'Estes'),
(53, 9, 'Brittany', 'Pope'),
(54, 9, 'Gunnar', 'Stanton'),
(55, 9, 'Jaycee', 'Galindo'),
(56, 9, 'Salvatore', 'Enriquez'),
(57, 9, 'Nellie', 'Briggs'),
(58, 9, 'Case', 'Marks'),
(59, 9, 'Monica', 'Cortes'),
(60, 9, 'Banks', 'Gregory'),
(61, 9, 'Alaya', 'Wilkinson'),
(62, 9, 'Leonard', 'Cuevas'),
(63, 9, 'Adele', 'Ballard'),
(64, 9, 'Kenzo', 'Lewis'),
(65, 9, 'Ellie', 'Sharp'),
(66, 9, 'Royce', 'Malone'),
(67, 9, 'Skyler', 'Waller'),
(68, 9, 'Marley', 'Horne'),
(69, 9, 'Marlowe', 'Mosley'),
(70, 9, 'Rayden', 'Lindsey'),
(71, 9, 'Colette', 'Hogan'),
(72, 9, 'Sonny', 'Powers'),
(73, 9, 'Michelle', 'Molina'),
(74, 9, 'Prince', 'Owens'),
(75, 9, 'Amaya', 'Hutchinson'),
(76, 9, 'Korbin', 'Woods'),
(77, 9, 'Reese', 'Macias'),
(78, 9, 'Moshe', 'Nash'),
(79, 9, 'Novah', 'Rivers'),
(80, 9, 'Bear', 'Nicholson');

-- --------------------------------------------------------

--
-- Table structure for table `work_fields`
--

CREATE TABLE `work_fields` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `work_fields`
--

INSERT INTO `work_fields` (`id`, `name`) VALUES
(52, ''),
(41, ' Advertising & Marketing'),
(37, ' Graphic & Digital Design'),
(50, 'Academic & Research Fields'),
(38, 'Animation & Game Development'),
(48, 'Cloud Computing & DevOps'),
(43, 'Corporate & Freelance Opportunities'),
(36, 'Corporate & Human Resources'),
(46, 'Cybersecurity & IT Infrastructure'),
(45, 'Data Science & Artificial Intelligence'),
(49, 'Database & Systems Administration'),
(34, 'Education & Research'),
(51, 'Emerging Technologies'),
(39, 'Film & Video Production'),
(47, 'Game Development'),
(35, 'Government & Non-Profit Organizations'),
(33, 'Healthcare & Mental Health'),
(42, 'Photography & Illustration'),
(32, 'Social Services & Community Work'),
(44, 'Software Development & Engineering'),
(40, 'Web & App Development');

-- --------------------------------------------------------

--
-- Table structure for table `work_titles`
--

CREATE TABLE `work_titles` (
  `id` int(11) NOT NULL,
  `course_id` int(11) NOT NULL,
  `work_field_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `work_titles`
--

INSERT INTO `work_titles` (`id`, `course_id`, `work_field_id`, `title`) VALUES
(76, 31, 32, 'Social Worker'),
(77, 31, 32, 'Community Development Officer'),
(78, 31, 32, 'Case Manager'),
(79, 31, 32, 'Outreach Coordinator'),
(80, 31, 33, 'Medical Social Worker (hospitals, clinics)'),
(81, 31, 33, 'Mental Health Counselor'),
(82, 31, 33, 'Rehabilitation Specialist'),
(83, 31, 34, 'School Social Worker'),
(84, 31, 34, 'Research Assistant'),
(85, 31, 35, 'Social Welfare Officer'),
(86, 31, 35, 'Human Rights Advocate'),
(87, 31, 35, 'Disaster Relief Coordinator'),
(88, 31, 36, 'Employee Assistance Program (EAP) Specialist'),
(89, 31, 36, 'Corporate Social Responsibility (CSR) Coordinator'),
(90, 32, 37, 'Graphic Designer'),
(91, 32, 37, 'UI/UX Designer'),
(92, 32, 37, 'Branding Specialist'),
(93, 32, 38, '2D/3D Animator'),
(94, 32, 38, 'Game Designer'),
(95, 32, 38, 'Motion Graphics Artist'),
(96, 32, 39, 'Video Editor'),
(97, 32, 39, 'Cinematographer'),
(98, 32, 39, 'Visual Effects (VFX) Artist'),
(99, 32, 40, 'Web Designer'),
(100, 32, 40, 'Frontend Developer'),
(101, 32, 40, 'Interactive Media Designer'),
(102, 32, 41, 'Digital Marketer'),
(103, 32, 41, 'Content Creator'),
(104, 32, 41, 'Social Media Manager'),
(105, 32, 42, 'Photographer'),
(106, 32, 42, 'Illustrator'),
(107, 32, 42, 'Concept Artist'),
(108, 32, 43, 'Multimedia Specialist'),
(109, 32, 43, 'Creative Director'),
(110, 32, 43, 'Freelancer (various digital arts fields)'),
(111, 33, 44, 'Software Developer / Engineer'),
(112, 33, 44, 'Web Developer (Frontend, Backend, Full Stack)'),
(113, 33, 44, 'Mobile App Developer'),
(114, 33, 45, 'Data Scientist'),
(115, 33, 45, 'Machine Learning Engineer'),
(116, 33, 45, 'AI Developer'),
(117, 33, 46, 'Cybersecurity Analyst'),
(118, 33, 46, 'Network Administrator'),
(119, 33, 46, 'IT Support Specialist'),
(120, 33, 47, 'Game Developer'),
(121, 33, 47, 'Game Designer'),
(122, 33, 47, 'Game Tester'),
(123, 33, 48, 'Cloud Engineer'),
(124, 33, 48, 'DevOps Engineer'),
(125, 33, 48, 'Site Reliability Engineer (SRE)'),
(126, 33, 49, 'Database Administrator'),
(127, 33, 49, 'System Analyst'),
(128, 33, 49, 'IT Consultant'),
(129, 33, 50, 'Computer Science Instructor'),
(130, 33, 50, 'Researcher (AI, robotics, algorithms)'),
(131, 33, 51, 'Blockchain Developer'),
(132, 33, 51, 'Internet of Things (IoT) Specialist'),
(133, 33, 51, 'Quantum Computing Researcher'),
(134, 32, 52, 'd'),
(135, 31, 52, 'f'),
(136, 32, 52, 'dsfs'),
(137, 33, 52, 'dsfsdf'),
(138, 32, 52, 'dfgfdg'),
(139, 34, 52, 'haha'),
(140, 34, 52, 'sdfs'),
(141, 33, 52, 'sdf'),
(142, 33, 52, 'sd');

-- --------------------------------------------------------

--
-- Table structure for table `yearbooks`
--

CREATE TABLE `yearbooks` (
  `id` int(11) NOT NULL,
  `folder_name` varchar(255) NOT NULL,
  `yearbook_name` varchar(255) NOT NULL,
  `date_uploaded` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `yearbooks`
--

INSERT INTO `yearbooks` (`id`, `folder_name`, `yearbook_name`, `date_uploaded`) VALUES
(9, 'YearBook 2021', 'Yearbook 2025', '2025-02-27 16:31:41'),
(10, 'pictures', 'Yearbook 2025', '2025-04-24 10:35:04');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `alumni`
--
ALTER TABLE `alumni`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `alumni_card_number` (`alumni_card_number`);

--
-- Indexes for table `alumni_ids`
--
ALTER TABLE `alumni_ids`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `alumni_id` (`alumni_id`);

--
-- Indexes for table `alumni_survey`
--
ALTER TABLE `alumni_survey`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `courses`
--
ALTER TABLE `courses`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `email_verifications`
--
ALTER TABLE `email_verifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `events`
--
ALTER TABLE `events`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `images`
--
ALTER TABLE `images`
  ADD PRIMARY KEY (`id`),
  ADD KEY `yearbook_id` (`yearbook_id`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `posts`
--
ALTER TABLE `posts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `students`
--
ALTER TABLE `students`
  ADD PRIMARY KEY (`id`),
  ADD KEY `yearbook_id` (`yearbook_id`);

--
-- Indexes for table `work_fields`
--
ALTER TABLE `work_fields`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- Indexes for table `work_titles`
--
ALTER TABLE `work_titles`
  ADD PRIMARY KEY (`id`),
  ADD KEY `course_id` (`course_id`),
  ADD KEY `work_field_id` (`work_field_id`);

--
-- Indexes for table `yearbooks`
--
ALTER TABLE `yearbooks`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `alumni`
--
ALTER TABLE `alumni`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=47;

--
-- AUTO_INCREMENT for table `alumni_ids`
--
ALTER TABLE `alumni_ids`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=223;

--
-- AUTO_INCREMENT for table `alumni_survey`
--
ALTER TABLE `alumni_survey`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `courses`
--
ALTER TABLE `courses`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=35;

--
-- AUTO_INCREMENT for table `email_verifications`
--
ALTER TABLE `email_verifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `events`
--
ALTER TABLE `events`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=20;

--
-- AUTO_INCREMENT for table `images`
--
ALTER TABLE `images`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=691;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=23;

--
-- AUTO_INCREMENT for table `posts`
--
ALTER TABLE `posts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=56;

--
-- AUTO_INCREMENT for table `students`
--
ALTER TABLE `students`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=81;

--
-- AUTO_INCREMENT for table `work_fields`
--
ALTER TABLE `work_fields`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=53;

--
-- AUTO_INCREMENT for table `work_titles`
--
ALTER TABLE `work_titles`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=143;

--
-- AUTO_INCREMENT for table `yearbooks`
--
ALTER TABLE `yearbooks`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `email_verifications`
--
ALTER TABLE `email_verifications`
  ADD CONSTRAINT `email_verifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `alumni` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `events`
--
ALTER TABLE `events`
  ADD CONSTRAINT `events_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `alumni` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `images`
--
ALTER TABLE `images`
  ADD CONSTRAINT `images_ibfk_1` FOREIGN KEY (`yearbook_id`) REFERENCES `yearbooks` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `posts`
--
ALTER TABLE `posts`
  ADD CONSTRAINT `posts_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `alumni` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `students`
--
ALTER TABLE `students`
  ADD CONSTRAINT `students_ibfk_1` FOREIGN KEY (`yearbook_id`) REFERENCES `yearbooks` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `work_titles`
--
ALTER TABLE `work_titles`
  ADD CONSTRAINT `work_titles_ibfk_1` FOREIGN KEY (`course_id`) REFERENCES `courses` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `work_titles_ibfk_2` FOREIGN KEY (`work_field_id`) REFERENCES `work_fields` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
