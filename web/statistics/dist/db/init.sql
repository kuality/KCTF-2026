-- MariaDB dump 10.19  Distrib 10.5.13-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: medical
-- ------------------------------------------------------
-- Server version       10.5.13-MariaDB-1:10.5.13+maria~focal

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `medical`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `medical` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;

USE `medical`;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `flag`;

CREATE TABLE `flag_838ece1033` (
  `flag` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `THIS_IS_FAKE_FLAG_TABLE` (flag) VALUES('KCTF{THIS_IS_FAKE_FLAG}');

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `name` varchar(100) NOT NULL,
  `birthday` varchar(100) NOT NULL,
  `status` varchar(100) NOT NULL,
  `medical_status` varchar(100) NOT NULL,
  `medical_subjects` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

INSERT INTO users (name, birthday, status, medical_status, medical_subjects) VALUES 
    ('홍길동', '1985-03-15', '입원 중', '3회 출석 예정', '내과'), 
    ('김영희', '1990-07-22', '입원 예정', '2회 출석 예정', '관절'), 
    ('이철수', '1978-11-05', '퇴실', '완료', '심장과'), 
    ('박민지', '2001-02-28', '입원 중', '1회 출석 예정', '소화기내과'), 
    ('최수호', '1965-12-12', '퇴실', '완료', '내분비내과'), 
    ('정다은', '1988-05-30', '입원 중', '4회 출석 예정', '감염내과'), 
    ('송지우', '1995-09-17', '입원 예정', '3회 출석 예정', '호흡기내과'), 
    ('김도현', '1972-01-03', '퇴실', '완료', '혈액종양내과'), 
    ('이수민', '2000-06-25', '입원 중', '2회 출석 예정', '알레르기내과'), 
    ('박재현', '1982-10-09', '입원 예정', '1회 출석 예정', '신장내과');

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-06-28 11:48:14