/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50527
Source Host           : localhost:3306
Source Database       : hehe

Target Server Type    : MYSQL
Target Server Version : 50527
File Encoding         : 65001

Date: 2019-06-08 19:16:26
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for `npcswitch`
-- ----------------------------
DROP TABLE IF EXISTS `npcswitch`;
CREATE TABLE `npcswitch` (
  `sceneID` int(11) NOT NULL DEFAULT '0' COMMENT '仅储存改变值，而预设值从配置文件中读取即可，另外不储存副本的值',
  `npcIndex` int(11) NOT NULL DEFAULT '0',
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` int(1) DEFAULT NULL,
  PRIMARY KEY (`sceneID`,`npcIndex`,`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of npcswitch
-- ----------------------------

-- ----------------------------
-- Table structure for `playerstring`
-- ----------------------------
DROP TABLE IF EXISTS `playerstring`;
CREATE TABLE `playerstring` (
  `uid` int(11) NOT NULL DEFAULT '0',
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` longtext,
  PRIMARY KEY (`uid`,`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of playerstring
-- ----------------------------

-- ----------------------------
-- Table structure for `playerswitch`
-- ----------------------------
DROP TABLE IF EXISTS `playerswitch`;
CREATE TABLE `playerswitch` (
  `uid` int(11) NOT NULL DEFAULT '0',
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` int(1) DEFAULT NULL,
  PRIMARY KEY (`uid`,`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of playerswitch
-- ----------------------------

-- ----------------------------
-- Table structure for `playervariable`
-- ----------------------------
DROP TABLE IF EXISTS `playervariable`;
CREATE TABLE `playervariable` (
  `uid` int(11) NOT NULL DEFAULT '0',
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`uid`,`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of playervariable
-- ----------------------------

-- ----------------------------
-- Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` bigint(20) NOT NULL DEFAULT '0',
  `sid` varchar(64) DEFAULT NULL,
  `sceneID` int(11) NOT NULL DEFAULT '0',
  `data` longtext,
  PRIMARY KEY (`id`,`sceneID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `worlddata`;
CREATE TABLE `worlddata` (
  `id` int(11) NOT NULL DEFAULT '0',
  `data` longtext,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of worlddata
-- ----------------------------
INSERT INTO `worlddata` VALUES ('1', '{}');

-- ----------------------------
-- Table structure for `worldstring`
-- ----------------------------
DROP TABLE IF EXISTS `worldstring`;
CREATE TABLE `worldstring` (
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` longtext,
  PRIMARY KEY (`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of worldstring
-- ----------------------------

-- ----------------------------
-- Table structure for `worldswitch`
-- ----------------------------
DROP TABLE IF EXISTS `worldswitch`;
CREATE TABLE `worldswitch` (
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` int(1) DEFAULT NULL,
  PRIMARY KEY (`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of worldswitch
-- ----------------------------

-- ----------------------------
-- Table structure for `worldvariable`
-- ----------------------------
DROP TABLE IF EXISTS `worldvariable`;
CREATE TABLE `worldvariable` (
  `varID` int(11) NOT NULL DEFAULT '0',
  `varValue` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`varID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of worldvariable
-- ----------------------------
