import React from "react";
import Team from "../../../components/team";
import AboutData from "../../../data/global/about.json";

const TeamContainer = () => {
    return (
        <div className="team-area">
            <div className="container">
                <div className="row">
                    <div className="col-lg-12" data-aos="fade-up">
                        <h2 className="title">{AboutData[2].title}</h2>
                    </div>
                </div>
                <div className="row">
                    {AboutData[2].team &&
                        AboutData[2].team.map((single, key) => {
                            return (
                                <div
                                    className="col-sm-6 col-md-3"
                                    key={key}
                                    data-aos="fade-up"
                                >
                                    <Team data={single} />
                                </div>
                            );
                        })}
                </div>
            </div>
        </div>
    );
};

export default TeamContainer;
